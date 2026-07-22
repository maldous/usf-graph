"""P0-8: leases, fencing tokens, claim reconciliation, CAS integrity."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from usf_factory.event_store import SideEffectQuotaExceeded, open_store
from usf_factory.ids import cycle_id, ulid


@pytest.fixture
def store(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    yield st
    st.close()


@pytest.mark.unit
def test_only_one_coordinator_lease(store):
    t1 = store.acquire_lease("coordinator", "A", "2099-01-01T00:00:00Z")
    assert t1 is not None
    assert store.acquire_lease("coordinator", "B", "2099-01-01T00:00:00Z") is None
    store.release_lease("coordinator", "A", t1)
    t2 = store.acquire_lease("coordinator", "B", "2099-01-01T00:00:00Z")
    assert t2 is not None and t2 > t1


@pytest.mark.unit
def test_fencing_token_supersedes(store):
    t1 = store.acquire_lease("x", "A", "2000-01-01T00:00:00Z")  # already expired
    reaped = store.reap_expired_leases()
    assert "x" in reaped
    t2 = store.acquire_lease("x", "B", "2099-01-01T00:00:00Z")
    assert store.lease_token_current("x", t2)
    assert not store.lease_token_current("x", t1)  # stale holder fenced out


@pytest.mark.unit
def test_lease_renew_only_by_current_holder(store):
    t = store.acquire_lease("c", "A", "2099-01-01T00:00:00Z")
    assert store.renew_lease("c", "A", t, "2099-02-01T00:00:00Z")
    assert not store.renew_lease("c", "A", t + 999, "2099-02-01T00:00:00Z")
    assert not store.renew_lease("c", "B", t, "2099-02-01T00:00:00Z")


@pytest.mark.adversarial
def test_expired_lease_and_claim_cannot_renew(store):
    lease = store.acquire_lease("expired", "A", "2000-01-01T00:00:00Z")
    assert lease is not None
    assert not store.renew_lease("expired", "A", lease, "2099-01-01T00:00:00Z")
    claim = store.claim_packet_fenced("expired-p", "r", "A", "2000-01-01T00:00:00Z")
    assert claim is not None
    assert not store.renew_claim("expired-p", "r", claim, "2099-01-01T00:00:00Z")


@pytest.mark.unit
def test_claim_fencing_and_reaping(store):
    tok = store.claim_packet_fenced("p", "r1", "o", "2099-01-01T00:00:00Z")
    assert tok is not None
    assert store.claim_packet_fenced("p", "r2", "o", "2099-01-01T00:00:00Z") is None
    assert store.claim_token_current("p", tok)
    # An expired claim is reclaimable and its token is no longer current.
    store.claim_packet_fenced("p2", "r", "o", "2000-01-01T00:00:00Z")
    assert "p2" in store.reap_expired_claims()


@pytest.mark.unit
def test_cas_integrity_roundtrip(store):
    ref = store.cas_put_text("some patch bytes")
    assert store.cas_get(ref) == b"some patch bytes"
    assert store.cas_put_text("some patch bytes") == ref  # dedup


@pytest.mark.unit
def test_budget_reservation(store):
    from usf_factory.budget import BudgetLedger, BudgetLimits

    led = BudgetLedger(store, BudgetLimits(global_usd=1.0))
    # Free/local reserves 0 and always succeeds.
    assert led.reserve(cycle_id="c", provider_id="ollama", estimate_usd=0.0)[0] is True
    # Within budget.
    assert led.reserve(cycle_id="c", provider_id="p", estimate_usd=0.6)[0] is True
    # Over budget is refused.
    ok, why = led.reserve(cycle_id="c", provider_id="p", estimate_usd=0.6)
    assert ok is False and "global" in why


@pytest.mark.adversarial
def test_paid_budget_reservation_is_atomic_across_process_connections(tmp_path):
    from usf_factory.budget import BudgetLedger, BudgetLimits

    db_path = tmp_path / "budget.sqlite"
    cas_path = tmp_path / "cas"
    open_store(db_path, cas_path).close()
    barrier = Barrier(2)

    def reserve(name: str) -> bool:
        local = open_store(db_path, cas_path)
        try:
            barrier.wait()
            return BudgetLedger(local, BudgetLimits(global_usd=1.0)).reserve_exact(
                reservation_id=name,
                cycle_id="cycle",
                provider_id="paid",
                estimate_usd=0.75,
            )[0]
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, ["one", "two"]))
    assert sorted(results) == [False, True]


@pytest.mark.adversarial
def test_actual_cost_overrun_is_persisted_and_blocks_future_budget(store):
    from usf_factory.budget import BudgetLedger, BudgetLimits

    ledger = BudgetLedger(store, BudgetLimits(global_usd=1.0))
    assert ledger.reserve_exact(
        reservation_id="first",
        cycle_id="cycle",
        provider_id="paid",
        estimate_usd=0.5,
    )[0]
    within, reason = ledger.commit(
        reservation_id="first",
        cycle_id="cycle",
        provider_id="paid",
        estimate_usd=0.5,
        actual_usd=1.25,
    )
    assert within is False and "exceeded" in reason
    assert store.get("budget_reservations", "first")["over_budget"] is True
    assert (
        ledger.reserve_exact(
            reservation_id="second",
            cycle_id="cycle",
            provider_id="paid",
            estimate_usd=0.01,
        )[0]
        is False
    )


@pytest.mark.adversarial
def test_free_provider_daily_request_limit_is_atomic(store):
    from usf_factory.budget import BudgetLedger, BudgetLimits

    ledger = BudgetLedger(store, BudgetLimits(global_usd=0.0, daily_requests=1))
    assert ledger.reserve_exact(
        reservation_id="free-one",
        cycle_id="cycle",
        provider_id="free-provider",
        estimate_usd=0.0,
    )[0]
    ok, reason = ledger.reserve_exact(
        reservation_id="free-two",
        cycle_id="cycle",
        provider_id="free-provider",
        estimate_usd=0.0,
    )
    assert ok is False and "daily request limit" in reason


@pytest.mark.adversarial
def test_atomic_side_effect_quota_allows_only_one_concurrent_reservation(tmp_path):
    db_path = tmp_path / "quota.sqlite"
    cas_path = tmp_path / "cas"
    first = open_store(db_path, cas_path)
    first.close()
    barrier = Barrier(2)

    def reserve(delivery: str) -> str:
        local = open_store(db_path, cas_path)
        try:
            barrier.wait()
            local.persist_delivery_transition(
                delivery_id=delivery,
                expected_revision=0,
                record_payload={
                    "delivery_id": delivery,
                    "obligation_id": delivery,
                    "state": "UNCERTAIN_SIDE_EFFECT",
                    "version": 0,
                },
                from_state="",
                to_state="UNCERTAIN_SIDE_EFFECT",
                input_ref="cas:sha256:" + "1" * 64,
                assurance_bundle_ref="cas:sha256:" + "2" * 64,
                authorization_digest="sha256:" + "a" * 64,
                note_code="intent:merge",
                reservation={
                    "consumption_id": f"effect-{delivery}",
                    "protected_action": "main_integration",
                    "effect": "merge",
                    "quota_name": "pr_merges",
                    "quota_limit": 1,
                },
            )
            return "reserved"
        except SideEffectQuotaExceeded:
            return "rejected"
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = sorted(pool.map(reserve, ["d1", "d2"]))
    assert results == ["rejected", "reserved"]
    check = open_store(db_path, cas_path)
    try:
        assert check.count("authorization_consumptions", "status IN ('reserved','consumed')") == 1
        assert check.count("delivery_transitions") == 1
    finally:
        check.close()


@pytest.mark.unit
def test_transition_projection_event_and_consumption_commit_together(store):
    revision, ref = store.persist_delivery_transition(
        delivery_id="d",
        expected_revision=0,
        record_payload={
            "delivery_id": "d",
            "obligation_id": "o",
            "state": "UNCERTAIN_SIDE_EFFECT",
            "version": 0,
        },
        from_state="",
        to_state="UNCERTAIN_SIDE_EFFECT",
        input_ref="cas:sha256:" + "1" * 64,
        assurance_bundle_ref="cas:sha256:" + "2" * 64,
        authorization_digest="sha256:" + "a" * 64,
        note_code="intent:publish",
        reservation={
            "consumption_id": "effect-d-publish",
            "protected_action": "stardog_publication",
            "effect": "publish",
            "quota_name": "authority_publications",
            "quota_limit": 1,
        },
    )
    assert revision == 1 and store.cas_has(ref)
    projection = store.get("delivery_records", "d")
    assert projection and projection["version"] == 1 and projection["transition_ref"] == ref
    assert store.count("delivery_transitions") == 1
    consumption = store.get("authorization_consumptions", "effect-d-publish")
    assert consumption and consumption["status"] == "reserved"


@pytest.mark.unit
def test_ulid_is_sortable_and_unique():
    ids = [ulid() for _ in range(100)]
    assert len(set(ids)) == 100
    # The time prefix is non-decreasing; random suffixes intentionally have no
    # ordering guarantee within the same millisecond.
    assert [value[:10] for value in ids] == sorted(value[:10] for value in ids)
    a = cycle_id()
    assert a.startswith("cyc-") and len(a) == 30
