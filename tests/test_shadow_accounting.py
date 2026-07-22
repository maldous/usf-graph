"""S7: --shadow-packets accounting. Packets intentionally deferred by the cap are
never counted as missing/failed results."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.engine import FactoryEngine
from usf_factory.enums import PacketResultStatus, RunMode
from usf_factory.models import Packet, PacketResult, PacketSet


def _packets(n=3):
    return [
        Packet(
            obligation_id=f"o{i}",
            snapshot_id="s",
            authority_digest="a",
            base_head="h",
            objective="x",
            task_class="semantic-planning",
        )
        for i in range(n)
    ]


@pytest.mark.e2e
def test_shadow_cap_defers_are_not_missing(ctx):
    pkts = _packets(3)
    pset = PacketSet(
        snapshot_id="s",
        graph_id="g",
        packets=pkts,
        selected_packet_ids=[p.packet_id for p in pkts],
    )
    eng = FactoryEngine(ctx, max_shadow_packets=1)

    async def fake_one(packet, cycle_id, mode):
        return PacketResult(
            packet_id=packet.packet_id,
            status=PacketResultStatus.COMPLETED,
            agent_profile_id="a",
            analysis_ref="cas:x",
        )

    eng._execute_one = fake_one  # type: ignore[assignment]
    eng._coordinator_token = ctx.store.acquire_lease("coordinator", "cyc", "2999-01-01T00:00:00Z")
    assert eng._coordinator_token is not None
    results = asyncio.run(eng.execute_packets(pset, RunMode.SHADOW, "cyc"))

    assert len(results) == 1  # exactly one dispatched
    assert len(eng._dispatched_packet_ids) == 1
    # Missing is computed against the DISPATCHED set, so it is empty here.
    results_by_pid = {r.packet_id for r in results}
    dispatched = eng._dispatched_packet_ids
    missing = [pid for pid in dispatched if pid not in results_by_pid]
    assert missing == []  # the one dispatched packet produced a result
    # The other two are intentionally deferred, NOT missing.
    deferred = [pid for pid in pset.selected_packet_ids if pid not in dispatched]
    assert len(deferred) == 2


@pytest.mark.adversarial
def test_no_cap_dispatches_all(ctx):
    pkts = _packets(3)
    pset = PacketSet(
        snapshot_id="s",
        graph_id="g",
        packets=pkts,
        selected_packet_ids=[p.packet_id for p in pkts],
    )
    eng = FactoryEngine(ctx)  # no cap

    async def fake_one(packet, cycle_id, mode):
        return PacketResult(
            packet_id=packet.packet_id, status=PacketResultStatus.COMPLETED, agent_profile_id="a"
        )

    eng._execute_one = fake_one  # type: ignore[assignment]
    eng._coordinator_token = ctx.store.acquire_lease("coordinator", "cyc", "2999-01-01T00:00:00Z")
    assert eng._coordinator_token is not None
    results = asyncio.run(eng.execute_packets(pset, RunMode.SHADOW, "cyc"))
    assert len(results) == 3 and len(eng._dispatched_packet_ids) == 3
