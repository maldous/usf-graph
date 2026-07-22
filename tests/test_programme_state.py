"""P0-1: obligations derived from live programme state (not fixtures)."""

from __future__ import annotations

import asyncio

import pytest

from conftest import FakeAuthority
from usf_factory.engine import FactoryEngine
from usf_factory.enums import RunMode
from usf_factory.errors import SnapshotError
from usf_factory.models import Packet
from usf_factory.programme_state import parse_programme_obligations
from usf_factory.snapshots import _complete_work_plan


@pytest.mark.unit
def test_parse_programme_obligations_from_work_plan():
    wp = {
        "items": [
            {"id": "A", "title": "root fix", "dependencies": []},
            {"id": "B", "title": "depends on A", "dependsOn": ["A"]},
        ]
    }
    obls = parse_programme_obligations({"openGaps": []}, wp)
    ids = {o["id"] for o in obls}
    assert ids == {"A", "B"}
    b = next(o for o in obls if o["id"] == "B")
    assert b["dependencies"] == ["A"]
    # No write scope from live authority => read-only analysis (no accidental mutation).
    assert "suggested_write_scope" not in b or not b.get("suggested_write_scope")


@pytest.mark.unit
def test_work_plan_pagination_is_complete_and_digest_bound():
    items = [{"id": f"O-{index}", "title": "work"} for index in range(121)]
    authority = FakeAuthority(digest="sha256:page-bound", work_plan_items=items)
    plan = _complete_work_plan(authority, "sha256:page-bound")
    assert len(plan["gaps"]) == 121
    assert {item["id"] for item in plan["gaps"]} == {f"O-{index}" for index in range(121)}


@pytest.mark.adversarial
def test_work_plan_pagination_fails_on_missing_or_moved_authority():
    class Broken(FakeAuthority):
        def work_plan(self, arguments=None):
            result = super().work_plan(arguments)
            payload = result.json()
            payload["authorityDigest"] = "sha256:moved"
            return self._tcr(payload)

    with pytest.raises(SnapshotError, match="differs from bootstrap"):
        _complete_work_plan(Broken(), "sha256:expected")


@pytest.mark.adversarial
def test_parser_rejects_duplicate_or_silently_oversized_work_plan():
    with pytest.raises(ValueError, match="duplicate"):
        parse_programme_obligations({}, {"items": [{"id": "A"}, {"id": "A"}]})
    with pytest.raises(ValueError, match="bounded obligation limit"):
        parse_programme_obligations({}, {"items": [{"id": f"O-{index}"} for index in range(1_001)]})


@pytest.mark.e2e
def test_only_dependency_ready_obligation_selected(ctx, tmp_usf):
    # Three obligations; C depends on A. Only dependency-ready ones may run.
    items = [
        {"id": "A", "title": "independent A", "dependencies": []},
        {"id": "B", "title": "independent B", "dependencies": []},
        {"id": "C", "title": "needs A", "dependsOn": ["A"]},
    ]

    def authority_factory():
        return FakeAuthority(work_plan_items=items)

    eng = FactoryEngine(ctx, authority_factory=authority_factory)
    receipt = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))

    pset = ctx.store.get("packet_sets", receipt.set_id)
    pk = {pid: Packet(**pl).obligation_id for pid, pl in ctx.store.items("packets")}
    selected = {pk[i] for i in pset["selected_packet_ids"]}
    deferred = {pk[i] for i in pset["deferred_packet_ids"]}
    assert "C" in deferred  # dependency not yet resolved
    assert "A" in selected and "B" in selected  # dependency-ready


@pytest.mark.e2e
def test_no_obligations_yields_readonly_verification(ctx, tmp_usf, fake_authority_factory):
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    receipt = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))
    pk = {pid: Packet(**pl).obligation_id for pid, pl in ctx.store.items("packets")}
    assert "obl-verify-current-state" in set(pk.values())
    # Verification packet is read-only (no write scope => private-metadata).
    for _pid, pl in ctx.store.items("packets"):
        assert Packet(**pl).write_paths == []
