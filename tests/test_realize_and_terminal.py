"""Spec Part B — terminal-completion stability rule + engine delivery wiring."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.canonical import canonical_json, content_digest, digest_text
from usf_factory.engine import FactoryEngine
from usf_factory.enums import (
    CycleState,
    PacketResultStatus,
    ProtectedAction,
    RemediationKind,
    Risk,
    RunMode,
)
from usf_factory.models import (
    ActionableGapIdentity,
    Packet,
    PacketResult,
    PacketSet,
    SemanticSnapshot,
    ValidationReceipt,
    WavePatch,
    WaveReview,
)
from usf_factory.run_authorization import RunAuthorization
from usf_factory.validation import compute_terminal_complete, record_terminal_observation

FUTURE = "2999-01-01T00:00:00Z"


def _snap(digest="sha256:" + "a" * 64, *, unresolved=None, health=True):
    return SemanticSnapshot(
        authority_digest=digest,
        repository_head="head000",
        working_tree_digest="wt000",
        unresolved_obligations=list(unresolved or []),
        actionable_gap_identities=(
            [{"type": "test-gap", "subject": item} for item in (unresolved or [])]
        ),
        work_plan_complete=True,
        work_plan_authority_digest=digest,
        health_ok=health,
    )


def _terminal_auth(ctx):
    ctx.run_authorization = RunAuthorization(
        authorization_id="terminal-test",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        permitted_actions=[ProtectedAction.TERMINAL_COMPLETION],
    )


def _complete_observation(ctx, cycle_id: str, snap: SemanticSnapshot) -> None:
    ctx.store.put("cycles", cycle_id, {"cycle_id": cycle_id, "state": "LEARNED"})
    record_terminal_observation(ctx, cycle_id, snap)


# --------------------------------------------------------------------------- #
# Terminal completion (§13): two consecutive stable zero-gap snapshots.
# --------------------------------------------------------------------------- #


@pytest.mark.e2e
def test_terminal_requires_two_stable_zero_gap_snapshots(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    _terminal_auth(ctx)
    # One completed cycle is insufficient.
    _complete_observation(ctx, "cycle-000001", _snap())
    ok1, r1 = compute_terminal_complete(ctx, _snap())
    assert ok1 is False and any("two distinct" in x for x in r1)
    # Re-evaluating the same cycle cannot manufacture stability.
    _complete_observation(ctx, "cycle-000001", _snap())
    assert compute_terminal_complete(ctx, _snap())[0] is False
    # A second distinct completed cycle at the same digest closes stability.
    _complete_observation(ctx, "cycle-000002", _snap())
    ok2, _r2 = compute_terminal_complete(ctx, _snap())
    assert ok2 is True


@pytest.mark.adversarial
def test_terminal_gap_resets_stability(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    _terminal_auth(ctx)
    _complete_observation(ctx, "cycle-000001", _snap())
    _complete_observation(ctx, "cycle-000002", _snap())
    # A gap appears => stability resets.
    okg, rg = compute_terminal_complete(ctx, _snap(unresolved=["obl-x"]))
    assert okg is False and any("unresolved" in x for x in rg)
    _complete_observation(ctx, "cycle-000003", _snap(unresolved=["obl-x"]))
    # The completed gap cycle invalidates the prior stable pair.
    ok, _r = compute_terminal_complete(ctx, _snap())
    assert ok is False


@pytest.mark.adversarial
def test_terminal_requires_run_authorization_even_when_absent(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    _complete_observation(ctx, "cycle-000001", _snap())
    _complete_observation(ctx, "cycle-000002", _snap())
    ok, reasons = compute_terminal_complete(ctx, _snap())
    assert ok is False
    assert any("RunAuthorization" in reason for reason in reasons)


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


@pytest.mark.adversarial
def test_blocked_or_incomplete_cycles_cannot_supply_terminal_stability(ctx, tmp_usf):
    ctx.config.safety.allow_terminal_completion = True
    _terminal_auth(ctx)
    for cycle_id, state in (("cycle-blocked", "BLOCKED"), ("cycle-running", "EXECUTING")):
        ctx.store.put("cycles", cycle_id, {"cycle_id": cycle_id, "state": state})
        record_terminal_observation(ctx, cycle_id, _snap())
    _complete_observation(ctx, "cycle-complete", _snap())
    complete, reasons = compute_terminal_complete(ctx, _snap())
    assert complete is False
    assert any("two distinct completed cycles" in reason for reason in reasons)
    assert list(ctx.store.items("terminal_stability")) == [
        (
            "cycle-complete",
            {
                "authority_digest": "sha256:" + "a" * 64,
                "cycle_id": "cycle-complete",
                "snapshot_id": _snap().snapshot_id,
                "work_plan_complete": True,
                "zero_gap": True,
            },
        )
    ]


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
            delivery_id = "delivery-fixture"
            pr_url = "https://fixture.invalid/pr/1"
            merge_commit = "merge-fixture"
            authority_digest_before = "sha256:" + "a" * 64
            authority_digest_after = "sha256:" + "b" * 64

            def __init__(self):
                self.reconciliation = {}

        return _Rec()


def _wave_bits(ctx):
    packet = Packet(
        obligation_id="obl-9",
        gap_identity=ActionableGapIdentity(type="test-gap", subject="obl-9"),
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
    patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+x=1\n"
    patch_ref = ctx.store.cas_put_text(patch)
    patch_digest = digest_text(patch)
    wave = WavePatch(
        set_id=pset.set_id,
        patch_digest=patch_digest,
        patch_ref=patch_ref,
        changed_paths=["a.py"],
    )
    snap = _snap()
    runner_bindings = {"unit-tests": "fixture"}
    receipt = ValidationReceipt(
        schema_version=2,
        set_id=pset.set_id,
        gates={"unit-tests": True},
        all_passed=True,
        patch_digest=patch_digest,
        patch_ref=patch_ref,
        integration_tree=content_digest({"head": snap.repository_head, "patch": patch_digest}),
        integration_head=snap.repository_head,
        repository_base_head=snap.repository_head,
        authority_digest=snap.authority_digest,
        required_gate_inventory=["unit-tests"],
        actual_runner_inventory=["unit-tests"],
        runner_bindings=runner_bindings,
        runner_inventory_digest=content_digest(runner_bindings),
        toolchain_bindings={"python": "fixture"},
        toolchain_inventory_digest=content_digest({"python": "fixture"}),
    )
    review_context = {"setId": pset.set_id, "effectiveDiff": patch}
    review_context_ref = ctx.store.cas_put_text(canonical_json(review_context))
    admission_payload = {"agent_profile_id": "rev-1", "roles": ["reviewer"]}
    admission_ref = ctx.store.cas_put_text(canonical_json(admission_payload))
    review = WaveReview(
        schema_version=2,
        set_id=pset.set_id,
        reviewer_profile_id="rev-1",
        approved=True,
        patch_digest=patch_digest,
        validation_receipt_digest=receipt.digest(),
        review_context_digest=content_digest(review_context),
        review_context_ref=review_context_ref,
        reviewer_provider_id="review-provider",
        reviewer_actual_model="review-model",
        reviewer_admission_digest=content_digest(admission_payload),
        reviewer_admission_ref=admission_ref,
        authoring_identities=["prov"],
        authoring_providers=["prov"],
        independence_determined=True,
    )
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
    assert inp.assurance_bundle_ref.startswith("cas:sha256:")
    assert inp.assurance_bundle_digest == inp.assurance_bundle_ref.removeprefix("cas:")


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


@pytest.mark.adversarial
@pytest.mark.parametrize("prior_state", ["INIT", "SNAPSHOT", "EXECUTING", "VALIDATING"])
def test_preflight_blocks_on_incomplete_prior_cycle(ctx, tmp_usf, prior_state):
    ctx.store.put(
        "cycles",
        "prior-cycle",
        {"cycle_id": "prior-cycle", "state": prior_state},
        extra={"state": prior_state},
    )
    result = FactoryEngine(ctx).preflight("new-cycle")
    assert result["cycleState"] == "BLOCKED"
    assert result["recoveredFrom"] == "prior-cycle"
    assert "requires explicit reconciliation" in result["blockers"][0]


@pytest.mark.e2e
def test_cycle_receipt_reports_completed_protected_publication(ctx, tmp_usf):
    eng = FactoryEngine(ctx)
    pset, *_rest = _wave_bits(ctx)
    ctx.store.put(
        "publication_receipts",
        f"{pset.set_id}:delivery",
        {
            "delivery_state": "COMPLETE",
            "published": True,
            "authority_digest_after": "sha256:" + "b" * 64,
        },
        extra={"set_id": pset.set_id},
    )
    receipt = eng._finish(
        "cycle-published",
        RunMode.AUTONOMOUS_SAFE,
        CycleState.COMPLETE,
        "2000-01-01T00:00:00Z",
        pset=pset,
    )
    assert receipt.published is True
    assert receipt.programme_terminal_complete is True
    assert receipt.authority_digest_after == "sha256:" + "b" * 64


@pytest.mark.unit
def test_cycle_receipt_preserves_publication_when_reconciliation_blocks(ctx, tmp_usf):
    eng = FactoryEngine(ctx)
    pset, *_rest = _wave_bits(ctx)
    ctx.store.put(
        "publication_receipts",
        f"{pset.set_id}:delivery",
        {
            "delivery_id": "delivery-1",
            "delivery_state": "AUTHORITY_PUBLISHED",
            "published": True,
            "authority_digest_before": "sha256:" + "a" * 64,
            "authority_digest_after": "sha256:" + "b" * 64,
            "reconciliation_result": "required",
        },
        extra={"set_id": pset.set_id},
    )
    receipt = eng._finish(
        "cycle-reconciliation-required",
        RunMode.SHADOW,
        CycleState.BLOCKED,
        "2000-01-01T00:00:00Z",
        pset=pset,
        blockers=["publication reconciliation required"],
    )
    assert receipt.published is True
    assert receipt.delivery_state == "AUTHORITY_PUBLISHED"
    assert receipt.reconciliation_result == "required"
    assert receipt.programme_terminal_complete is False


@pytest.mark.adversarial
def test_run_authorization_caps_packets_in_mutating_modes(ctx, tmp_usf, monkeypatch):
    ctx.run_authorization = RunAuthorization(
        authorization_id="packet-cap",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        max_packets_per_wave=1,
    )
    packets = [
        Packet(
            obligation_id=f"obl-{index}",
            snapshot_id="s",
            authority_digest="a",
            base_head="h",
            objective="x",
            task_class="semantic-planning",
            risk=Risk.LOW,
        )
        for index in range(3)
    ]
    pset = PacketSet(
        snapshot_id="s",
        graph_id="g",
        packets=packets,
        selected_packet_ids=[packet.packet_id for packet in packets],
    )
    engine = FactoryEngine(ctx)
    engine._coordinator_token = ctx.store.acquire_lease(
        "coordinator", "cycle", "2999-01-01T00:00:00Z"
    )
    assert engine._coordinator_token is not None

    async def no_op(_packet, _cycle_id, _mode):
        return None

    monkeypatch.setattr(engine, "_execute_one", no_op)
    asyncio.run(engine.execute_packets(pset, RunMode.AUTONOMOUS_SAFE, "cycle"))
    assert len(engine._dispatched_packet_ids) == 1


@pytest.mark.adversarial
def test_no_progress_threshold_is_durable_across_engine_instances(ctx, tmp_usf):
    ctx.config.budgets.max_no_progress_cycles = 2
    pset, _wave, snap, _receipt, _review, _results, _by_id = _wave_bits(ctx)
    assert FactoryEngine(ctx)._detect_no_progress(snap, pset) is False
    ctx.store.put(
        "cycles",
        "cycle-prior",
        {
            "cycle_id": "cycle-prior",
            "snapshot_id": snap.snapshot_id,
            "set_id": pset.set_id,
            "state": "LEARNED",
        },
        extra={"state": "LEARNED"},
    )
    assert FactoryEngine(ctx)._detect_no_progress(snap, pset) is True
