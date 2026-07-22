"""Spec Part B — terminal-completion stability rule + engine delivery wiring."""

from __future__ import annotations

import pytest

from usf_factory.engine import FactoryEngine
from usf_factory.enums import (
    PacketResultStatus,
    ProtectedAction,
    RemediationKind,
    Risk,
)
from usf_factory.models import (
    Packet,
    PacketResult,
    PacketSet,
    SemanticSnapshot,
    ValidationReceipt,
    WavePatch,
    WaveReview,
)
from usf_factory.run_authorization import RunAuthorization
from usf_factory.validation import compute_terminal_complete

FUTURE = "2999-01-01T00:00:00Z"


def _snap(digest="sha256:aaa", *, unresolved=None, health=True):
    return SemanticSnapshot(
        authority_digest=digest,
        repository_head="head000",
        working_tree_digest="wt000",
        unresolved_obligations=list(unresolved or []),
        health_ok=health,
    )


# --------------------------------------------------------------------------- #
# Terminal completion (§13): two consecutive stable zero-gap snapshots.
# --------------------------------------------------------------------------- #


@pytest.mark.e2e
def test_terminal_requires_two_stable_zero_gap_snapshots(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    # First zero-gap reading: NOT complete (stability not yet established).
    ok1, r1 = compute_terminal_complete(ctx, _snap())
    assert ok1 is False and any("second consecutive" in x for x in r1)
    # Second consecutive zero-gap reading with the SAME digest: complete.
    ok2, _r2 = compute_terminal_complete(ctx, _snap())
    assert ok2 is True


@pytest.mark.adversarial
def test_terminal_gap_resets_stability(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    compute_terminal_complete(ctx, _snap())  # one zero-gap
    # A gap appears => stability resets.
    okg, rg = compute_terminal_complete(ctx, _snap(unresolved=["obl-x"]))
    assert okg is False and any("unresolved" in x for x in rg)
    # A single zero-gap after a gap is again NOT complete (needs two consecutive).
    ok, _r = compute_terminal_complete(ctx, _snap())
    assert ok is False


@pytest.mark.adversarial
def test_terminal_requires_run_authorization_when_present(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    # A RunAuthorization is present but does NOT permit terminal completion.
    ctx.run_authorization = RunAuthorization(
        authorization_id="a",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        permitted_actions=[],
    )
    ok, r = compute_terminal_complete(ctx, _snap())
    assert ok is False and any("does not permit terminal completion" in x for x in r)


# --------------------------------------------------------------------------- #
# Engine delivery wiring: coordinator when authorized, prepare-only otherwise.
# --------------------------------------------------------------------------- #


class _FakeCoordinator:
    def __init__(self):
        self.delivered = []

    def deliver(self, inp):
        self.delivered.append(inp)

        class _Rec:
            state = "COMPLETE"

        return _Rec()


def _wave_bits(ctx):
    packet = Packet(
        obligation_id="obl-9",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="repository-implementation",
        risk=Risk.MEDIUM,
        write_paths=["a.py"],
        remediation_kind=RemediationKind.SOURCE_CHANGE,
    )
    pset = PacketSet(
        snapshot_id="s", graph_id="g", packets=[packet], selected_packet_ids=[packet.packet_id]
    )
    wave = WavePatch(set_id=pset.set_id, patch_digest="pd", patch_ref="", changed_paths=["a.py"])
    snap = _snap()
    receipt = ValidationReceipt(set_id=pset.set_id, all_passed=True)
    review = WaveReview(set_id=pset.set_id, reviewer_profile_id="rev-1", approved=True)
    result = PacketResult(
        packet_id=packet.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="prof-1",
        actual_provider="prov",
        actual_model="m",
    )
    return pset, wave, snap, receipt, review, [result], {packet.packet_id: packet}


@pytest.mark.e2e
def test_engine_invokes_coordinator_when_authorized(ctx, tmp_usf):
    ctx.config.safety.allow_push_pr = True
    ctx.run_authorization = RunAuthorization(
        authorization_id="a",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        repositories=["maldous/usf-graph"],
        permitted_actions=[ProtectedAction.PUSH_PR],
    )
    coord = _FakeCoordinator()
    eng = FactoryEngine(ctx, delivery_coordinator=coord)
    pset, wave, snap, receipt, review, results, by_id = _wave_bits(ctx)
    assert eng._deliver_wave(pset, wave, snap, snap, receipt, review, results, by_id) is None
    assert len(coord.delivered) == 1
    inp = coord.delivered[0]
    assert inp.obligation_id == "obl-9"
    assert inp.remediation_kind is RemediationKind.SOURCE_CHANGE
    assert inp.review_approved is True and inp.validation_passed is True


@pytest.mark.adversarial
def test_engine_propagates_protected_delivery_failure(ctx, tmp_usf):
    ctx.config.safety.allow_push_pr = True
    ctx.run_authorization = RunAuthorization(
        authorization_id="a",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        repositories=["maldous/usf-graph"],
        permitted_actions=[ProtectedAction.PUSH_PR],
    )

    class _BlockedCoordinator(_FakeCoordinator):
        def deliver(self, inp):
            self.delivered.append(inp)

            class _Rec:
                state = "BLOCKED"

            return _Rec()

    eng = FactoryEngine(ctx, delivery_coordinator=_BlockedCoordinator())
    pset, wave, snap, receipt, review, results, by_id = _wave_bits(ctx)
    assert (
        eng._deliver_wave(pset, wave, snap, snap, receipt, review, results, by_id)
        == "protected delivery did not complete: BLOCKED"
    )


@pytest.mark.e2e
def test_engine_prepare_only_without_authorization(ctx, tmp_usf):
    ctx.run_authorization = None  # not authorized => prepare-only, coordinator untouched
    coord = _FakeCoordinator()
    eng = FactoryEngine(ctx, delivery_coordinator=coord)
    pset, wave, snap, receipt, review, results, by_id = _wave_bits(ctx)
    assert eng._deliver_wave(pset, wave, snap, snap, receipt, review, results, by_id) is None
    assert coord.delivered == []
    rec = ctx.store.get("publication_receipts", f"{pset.set_id}:delivery")
    assert rec is not None and rec["prepared"] in (False, True)
