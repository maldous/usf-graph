"""Completion-task runtime tests: routing-driven execution, brokered mutation,
mode semantics, concurrency, heartbeat/fencing. All fixture-based; no /usf."""

from __future__ import annotations

import asyncio
import re
import subprocess

import pytest

from conftest import FakeAuthority, all_dimension_scores, seed_agent
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AdmissionRole, CycleState, RunMode
from usf_factory.models import Obligation, ObligationGraph
from usf_factory.workers import BrokeredWorker


class _InlinePlanner:
    """Deterministic planner returning a fixed obligation graph (test-only)."""

    def __init__(self, obligations):
        self._obs = obligations

    async def plan(self, snapshot, goal_constraints=None):
        return ObligationGraph(
            snapshot_id=snapshot.snapshot_id,
            obligations=[Obligation(**o) for o in self._obs],
            planner_profile_id="inline-test",
        )


def _writer_chat(content="x = 1\n", contents=None, finish_args=None):
    """A deterministic 'model' that writes every packet write path in turn, then
    finishes with durable analysis evidence. ``contents`` maps path -> content
    (falling back to ``content``); ``finish_args`` overrides the finish payload."""

    async def chat(messages, tools):
        user = next((m["content"] for m in messages if m.get("role") == "user"), "")
        m = re.search(r"write_paths=\[(.*?)\]", user)
        paths = re.findall(r"'([^']+)'", m.group(1)) if m else []
        written = sum(
            1
            for msg in messages
            if msg.get("role") == "tool"
            and isinstance(msg.get("content"), dict)
            and msg["content"].get("accepted")
        )
        if paths and written < len(paths):
            path = paths[written]
            return {
                "content": "",
                "tool_calls": [
                    {
                        "id": f"w{written}",
                        "name": "write_new_file",
                        "arguments": {"path": path, "content": (contents or {}).get(path, content)},
                    }
                ],
            }
        args = finish_args or {
            "status": "COMPLETED",
            "findings": ["objective satisfied; scoped work performed"],
            "criteria_results": {"all": True},
        }
        return {
            "content": "",
            "tool_calls": [{"id": "fin", "name": "finish_packet", "arguments": args}],
        }

    return chat


def _worker_factory(store, chat):
    def make(mode, agent):
        mutating = mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)
        return BrokeredWorker(chat, store=store, mutating=mutating)

    return make


def _usf_head(repo):
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()


@pytest.mark.e2e
def test_executing_mode_requires_worker_factory(ctx, tmp_usf, fake_authority_factory):
    ctx.config.safety.autonomous_safe_enabled = True
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)  # no worker_factory
    receipt = asyncio.run(eng.run_cycle(RunMode.APPROVE_WAVE))
    assert receipt.state is CycleState.BLOCKED
    assert any("worker runtime" in b for b in receipt.blockers)


@pytest.mark.e2e
def test_approve_wave_executes_fixture_packet_end_to_end(ctx, tmp_usf):
    # Enable gates ONLY in this in-memory test config (committed defaults stay off).
    ctx.config.safety.autonomous_safe_enabled = True
    ctx.config.egress.source_egress_enabled = True
    ctx.config.egress.provider_overrides = {"test-provider": ["private-source"]}
    head_before = _usf_head(tmp_usf)

    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PATCH_PRODUCER],
        scores=all_dimension_scores(),
    )
    planner = _InlinePlanner(
        [
            {
                "id": "obl-add-code",
                "root_cause": "add a generated module",
                "semantic_subjects": [],
                "dependencies": [],
                "required_outcomes": ["create gen/thing.py with a test"],
                "acceptance_criteria": ["file created"],
                "risk": "medium",
                "task_class": "repository-implementation",
                "suggested_read_scope": [],
                # The required unit-tests gate may never green-skip, so the
                # implementation packet carries its test within the write scope.
                "suggested_write_scope": ["gen/thing.py", "tests/test_thing.py"],
            }
        ]
    )
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=planner,
        worker_factory=_worker_factory(
            ctx.store,
            _writer_chat(
                contents={
                    "gen/thing.py": "x = 1\n",
                    "tests/test_thing.py": "def test_ok():\n    assert True\n",
                }
            ),
        ),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.APPROVE_WAVE))

    assert receipt.state is CycleState.LEARNED
    assert receipt.selected_packets == 1
    assert receipt.accepted_packets == 1  # real mutating packet accepted
    # A wave patch was produced and validation ran green — including REAL tests
    # (unit-tests may not green-skip; the wave carries its own test).
    waves = ctx.store.records("wave_patches")
    assert len(waves) == 1 and "gen/thing.py" in waves[0]["changed_paths"]
    vr = ctx.store.get("validation_receipts", receipt.set_id)
    assert vr["all_passed"] is True and vr["gates"].get("format") is True
    assert vr["gates"].get("unit-tests") is True  # ran for real, not n/a
    # Learning observed the outcome.
    assert ctx.store.count("observations") >= 1
    # /usf untouched.
    assert _usf_head(tmp_usf) == head_before
    assert eng.iso.assert_no_factory_worktrees() == []


@pytest.mark.e2e
def test_shadow_mode_executes_without_integration(ctx, tmp_usf):
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE],
        scores=all_dimension_scores(),
    )
    # A read-only (no write scope) analysis obligation.
    planner = _InlinePlanner(
        [
            {
                "id": "obl-analyze",
                "root_cause": "analyze",
                "semantic_subjects": [],
                "dependencies": [],
                "acceptance_criteria": ["analysis"],
                "risk": "low",
                "task_class": "semantic-planning",
                "suggested_read_scope": [],
                "suggested_write_scope": [],
            }
        ]
    )
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=planner,
        worker_factory=_worker_factory(ctx.store, _writer_chat()),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.SHADOW))
    assert receipt.state is CycleState.LEARNED
    assert ctx.store.count("packet_results") == 1
    # Shadow never produces a wave patch (no integration).
    assert ctx.store.count("wave_patches") == 0
    # The read-only completion carries a DURABLE analysis artifact in CAS.
    [(_rid, row)] = ctx.store.items("packet_results")
    assert row["analysis_ref"], "read-only completion must persist an analysis artifact"
    artifact = ctx.store.cas_get(row["analysis_ref"]).decode()
    assert "findings" in artifact


@pytest.mark.e2e
def test_concurrency_executes_four_packets(ctx, tmp_usf):
    ctx.config.safety.autonomous_safe_enabled = True
    ctx.config.budgets.max_concurrent_workers = 4
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE],
        scores=all_dimension_scores(),
    )
    obs = [
        {
            "id": f"O{i}",
            "root_cause": f"analyze {i}",
            "semantic_subjects": [],
            "dependencies": [],
            "acceptance_criteria": ["a"],
            "risk": "low",
            "task_class": "semantic-planning",
            "suggested_read_scope": [],
            "suggested_write_scope": [],
        }
        for i in range(4)
    ]
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=_InlinePlanner(obs),
        worker_factory=_worker_factory(ctx.store, _writer_chat()),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.SHADOW))
    assert receipt.selected_packets == 4
    assert ctx.store.count("packet_results") == 4


@pytest.mark.e2e
def test_failed_validation_blocks_and_does_not_credit_worker(ctx, tmp_usf):
    ctx.config.safety.autonomous_safe_enabled = True
    ctx.config.egress.source_egress_enabled = True
    ctx.config.egress.provider_overrides = {"test-provider": ["private-source"]}
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PATCH_PRODUCER],
        scores=all_dimension_scores(),
    )
    planner = _InlinePlanner(
        [
            {
                "id": "o",
                "root_cause": "add broken code",
                "semantic_subjects": [],
                "dependencies": [],
                "acceptance_criteria": ["c"],
                "risk": "medium",
                "task_class": "repository-implementation",
                "suggested_read_scope": [],
                "suggested_write_scope": ["gen/bad.py"],
            }
        ]
    )
    # Writes syntactically invalid Python => ruff format gate fails.
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=planner,
        worker_factory=_worker_factory(ctx.store, _writer_chat(content="def (:\n")),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.APPROVE_WAVE))
    assert receipt.state is CycleState.BLOCKED
    assert any("validation" in b for b in receipt.blockers)
    assert receipt.accepted_packets == 0
    # The worker must NOT be credited with a success (only integrated+validated wins).
    obs = ctx.store.records("observations", "agent_profile_id!=?", ("",))
    assert all(o.get("value") == 0.0 for o in obs) or obs == []


@pytest.mark.e2e
def test_no_route_blocks_the_wave(ctx, tmp_usf):
    ctx.config.safety.autonomous_safe_enabled = True
    # No seeded agent => scheduler selects nobody => the selected packet has no
    # result => the wave is BLOCKED (not a green LEARNED).
    planner = _InlinePlanner(
        [
            {
                "id": "o",
                "root_cause": "analyze",
                "semantic_subjects": [],
                "dependencies": [],
                "acceptance_criteria": ["c"],
                "risk": "low",
                "task_class": "semantic-planning",
                "suggested_read_scope": [],
                "suggested_write_scope": [],
            }
        ]
    )
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=planner,
        worker_factory=_worker_factory(ctx.store, _writer_chat()),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.APPROVE_WAVE))
    assert receipt.state is CycleState.BLOCKED
    assert any("no result" in b for b in receipt.blockers)


_READONLY_OBLIGATION = {
    "id": "obl-analyze",
    "root_cause": "analyze",
    "semantic_subjects": [],
    "dependencies": [],
    "acceptance_criteria": ["analysis"],
    "risk": "low",
    "task_class": "semantic-planning",
    "suggested_read_scope": [],
    "suggested_write_scope": [],
}


@pytest.mark.e2e
def test_failed_worker_result_blocks_cycle(ctx, tmp_usf):
    """A recorded FAILED result is not 'handled' — the cycle must BLOCK, never
    finish LEARNED merely because the failure was durably stored."""
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE],
        scores=all_dimension_scores(),
    )
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=_InlinePlanner([dict(_READONLY_OBLIGATION)]),
        worker_factory=_worker_factory(ctx.store, _writer_chat(finish_args={"status": "FAILED"})),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.SHADOW))
    assert receipt.state is CycleState.BLOCKED
    assert any("not accepted" in b for b in receipt.blockers)
    assert receipt.accepted_packets == 0


@pytest.mark.e2e
def test_readonly_completion_without_evidence_blocks(ctx, tmp_usf):
    """COMPLETED with no findings/criteria on a read-only packet is a worker
    failure (no durable work product) and blocks the cycle."""
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE],
        scores=all_dimension_scores(),
    )
    eng = FactoryEngine(
        ctx,
        authority_factory=lambda: FakeAuthority(),
        planner=_InlinePlanner([dict(_READONLY_OBLIGATION)]),
        worker_factory=_worker_factory(
            ctx.store,
            _writer_chat(finish_args={"status": "COMPLETED"}),  # no evidence
        ),
    )
    receipt = asyncio.run(eng.run_cycle(RunMode.SHADOW))
    assert receipt.state is CycleState.BLOCKED
    assert any("not accepted" in b for b in receipt.blockers)
    # The stored result is FAILED (worker-level fail-closed), not COMPLETED.
    rows = [row for _rid, row in ctx.store.items("packet_results")]
    assert rows and all(r["status"] == "FAILED" for r in rows)


@pytest.mark.e2e
def test_routing_selects_agent_and_execution_uses_it(ctx, tmp_usf):
    profile = seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE],
        scores=all_dimension_scores(),
    )
    planner = _InlinePlanner(
        [
            {
                "id": "obl-analyze",
                "root_cause": "analyze",
                "semantic_subjects": [],
                "dependencies": [],
                "acceptance_criteria": ["a"],
                "risk": "low",
                "task_class": "semantic-planning",
                "suggested_read_scope": [],
                "suggested_write_scope": [],
            }
        ]
    )
    seen = {}

    def wf(mode, agent):
        seen["agent"] = agent.profile_id
        return BrokeredWorker(_writer_chat(), store=ctx.store, mutating=False)

    eng = FactoryEngine(
        ctx, authority_factory=lambda: FakeAuthority(), planner=planner, worker_factory=wf
    )
    asyncio.run(eng.run_cycle(RunMode.SHADOW))
    assert seen.get("agent") == profile.profile_id  # routing decision drove execution
