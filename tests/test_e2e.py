"""End-to-end non-mutating cycle (build task §20).

Runs a complete cycle with a FAKE authority (no live MCP), a temporary /usf, and
the deterministic fixture planner: provider config -> snapshot -> plan -> packet
compilation -> dry-run scheduling/execution -> integration/review/validation.
Asserts no writes to /usf, no billable inference, and no secret leakage.
"""

from __future__ import annotations

import asyncio
import subprocess

import pytest

from usf_factory.engine import FactoryEngine
from usf_factory.enums import CycleState, RunMode


def _usf_head(repo):
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()


@pytest.mark.e2e
def test_full_non_mutating_cycle(ctx, tmp_usf, fake_authority_factory):
    head_before = _usf_head(tmp_usf)
    status_before = subprocess.run(
        ["git", "-C", str(tmp_usf), "status", "--porcelain"], capture_output=True, text=True
    ).stdout

    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    receipt = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))

    # Cycle completed the full non-mutating pipeline.
    assert receipt.state is CycleState.LEARNED
    assert receipt.selected_packets >= 1
    assert receipt.accepted_packets == 0  # dry-run accepts nothing for mutation
    assert receipt.published is False

    # Full pipeline events present.
    kinds = [e["kind"] for e in ctx.store.events(receipt.cycle_id)]
    for k in ("preflight", "snapshot.captured", "plan.compiled", "execute.done", "cycle.finished"):
        assert k in kinds

    # Durable artifacts persisted.
    assert ctx.store.count("semantic_snapshots") >= 1
    assert ctx.store.count("packet_sets") >= 1
    assert ctx.store.count("packets") >= 1
    assert ctx.store.count("integration_attempts") >= 1
    assert ctx.store.count("validation_receipts") >= 1

    # /usf was NOT modified.
    assert _usf_head(tmp_usf) == head_before
    status_after = subprocess.run(
        ["git", "-C", str(tmp_usf), "status", "--porcelain"], capture_output=True, text=True
    ).stdout
    assert status_after == status_before

    # No factory worktrees registered under /usf.
    assert eng.iso.assert_no_factory_worktrees() == []


@pytest.mark.e2e
def test_cycle_is_deterministic(ctx, tmp_usf, fake_authority_factory):
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    r1 = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))
    r2 = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))
    # Same authority + repo state => identical snapshot and packet set ids.
    assert r1.snapshot_id == r2.snapshot_id
    assert r1.set_id == r2.set_id


@pytest.mark.e2e
def test_autonomous_safe_is_blocked_by_default(ctx, tmp_usf, fake_authority_factory):
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    receipt = asyncio.run(eng.run_cycle(RunMode.AUTONOMOUS_SAFE))
    assert receipt.state is CycleState.BLOCKED
    assert any("autonomous_safe_enabled" in b for b in receipt.blockers)


@pytest.mark.e2e
def test_no_secret_values_in_sqlite(ctx, tmp_usf, fake_authority_factory, env_file):
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))
    # The two fake secret values from env_file must never appear in the DB bytes.
    db_bytes = ctx.paths.db_path.read_bytes()
    assert b"sk-test-not-real-value-000000" not in db_bytes
    assert b"gsk_testnotrealvalue00000" not in db_bytes


@pytest.mark.e2e
def test_publication_gate_blocks(ctx, tmp_usf):
    from usf_factory.validation import PublicationStateMachine

    sm = PublicationStateMachine(ctx)
    receipt = sm.publish("set1", authority_digest_before="d")
    assert receipt.published is False
    assert receipt.gate_enabled is False


@pytest.mark.e2e
def test_terminal_complete_not_from_prose(ctx, tmp_usf, fake_authority_factory):
    from usf_factory.validation import compute_terminal_complete

    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    eng.preflight("adhoc")
    snap = eng.capture_snapshot("adhoc")
    complete, reasons = compute_terminal_complete(ctx, snap)
    assert complete is False
    assert any("gate disabled" in r for r in reasons)
