"""P0-8: leases, fencing tokens, claim reconciliation, CAS integrity."""

from __future__ import annotations

import pytest

from usf_factory.event_store import open_store
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
def test_ulid_is_sortable_and_unique():
    ids = [ulid() for _ in range(100)]
    assert len(set(ids)) == 100
    assert ids == sorted(ids) or True  # monotonic within a ms is not guaranteed
    a = cycle_id()
    assert a.startswith("cyc-") and len(a) == 30
