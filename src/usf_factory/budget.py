"""Budget reservation ledger (review §9.5).

Atomically reserve estimated cost before dispatch, then commit the actual cost or
release the reservation. Prevents overrun across global/provider/cycle scopes.
Backed by the append-only ``budget_events`` log so spend is auditable and
reconstructable. Local/free providers reserve 0.
"""

from __future__ import annotations

from dataclasses import dataclass

from .clock import utc_now_iso
from .event_store import Store
from .ids import ulid


@dataclass
class BudgetLimits:
    global_usd: float = 0.0
    per_provider_usd: float = 0.0
    per_cycle_usd: float = 0.0
    daily_requests: int = 0


class BudgetLedger:
    def __init__(self, store: Store, limits: BudgetLimits) -> None:
        self.store = store
        self.limits = limits

    def _spent(self, where: str = "", params: tuple = ()) -> float:
        rows = self.store.records("budget_events", where or None, params)
        total = 0.0
        for r in rows:
            total += float(r.get("amount", 0.0))
        return total

    def spent_total(self) -> float:
        return self._spent()

    def spent_provider(self, provider_id: str) -> float:
        return self._spent("provider_id=?", (provider_id,))

    def spent_cycle(self, cycle_id: str) -> float:
        return self._spent("cycle_id=?", (cycle_id,))

    def reserve(self, *, cycle_id: str, provider_id: str, estimate_usd: float) -> tuple[bool, str]:
        """Try to reserve ``estimate_usd``. Returns (ok, reason). Zero cost always
        succeeds (free/local). Non-zero honours global/provider/cycle limits."""
        return self.reserve_exact(
            reservation_id=f"budget-{ulid()}",
            cycle_id=cycle_id,
            provider_id=provider_id,
            estimate_usd=estimate_usd,
        )

    def reserve_exact(
        self,
        *,
        reservation_id: str,
        cycle_id: str,
        provider_id: str,
        estimate_usd: float,
    ) -> tuple[bool, str]:
        """Atomically reserve money and one daily request under an idempotency key."""
        if estimate_usd < 0:
            return False, "negative estimate refused"
        day = utc_now_iso()[:10]
        with self.store.transaction(immediate=True):
            existing = self.store.get("budget_reservations", reservation_id)
            if existing is not None:
                same = (
                    existing.get("cycle_id") == cycle_id
                    and existing.get("provider_id") == provider_id
                    and float(existing.get("estimate_usd") or 0.0) == estimate_usd
                )
                return (same, "idempotent" if same else "reservation binding mismatch")
            active = self.store.records("budget_reservations", "status IN ('reserved','settled')")
            if self.limits.daily_requests:
                requests = sum(
                    1
                    for row in active
                    if row.get("provider_id") == provider_id and row.get("day") == day
                )
                if requests >= self.limits.daily_requests:
                    return False, f"provider {provider_id} daily request limit exceeded"
            global_spend = sum(float(row.get("charge_usd") or 0.0) for row in active)
            provider_spend = sum(
                float(row.get("charge_usd") or 0.0)
                for row in active
                if row.get("provider_id") == provider_id
            )
            cycle_spend = sum(
                float(row.get("charge_usd") or 0.0)
                for row in active
                if row.get("cycle_id") == cycle_id
            )
            if global_spend + estimate_usd > self.limits.global_usd:
                return False, "global budget exceeded"
            if (
                self.limits.per_provider_usd
                and provider_spend + estimate_usd > self.limits.per_provider_usd
            ):
                return False, f"provider {provider_id} budget exceeded"
            if self.limits.per_cycle_usd and cycle_spend + estimate_usd > self.limits.per_cycle_usd:
                return False, "cycle budget exceeded"
            payload = {
                "schema_version": 1,
                "reservation_id": reservation_id,
                "cycle_id": cycle_id,
                "provider_id": provider_id,
                "day": day,
                "estimate_usd": estimate_usd,
                "actual_usd": None,
                "charge_usd": estimate_usd,
                "status": "reserved",
                "over_budget": False,
            }
            self.store.put(
                "budget_reservations",
                reservation_id,
                payload,
                extra={
                    "cycle_id": cycle_id,
                    "provider_id": provider_id,
                    "status": "reserved",
                    "day": day,
                },
            )
            self._record(cycle_id, provider_id, estimate_usd, "reserve", reservation_id)
        return True, "free" if estimate_usd == 0 else "reserved"

    def commit(
        self,
        *,
        cycle_id: str,
        provider_id: str,
        estimate_usd: float,
        actual_usd: float,
        reservation_id: str | None = None,
    ) -> tuple[bool, str]:
        if actual_usd < 0:
            raise ValueError("actual cost cannot be negative")
        if reservation_id is None:
            self._record(cycle_id, provider_id, actual_usd - estimate_usd, "commit", "legacy")
            return True, "legacy settlement"
        with self.store.transaction(immediate=True):
            row = self.store.get("budget_reservations", reservation_id)
            if row is None or row.get("status") not in {"reserved", "settled"}:
                raise ValueError("budget reservation unavailable")
            if row.get("status") == "settled":
                return True, "idempotent"
            active = self.store.records("budget_reservations", "status IN ('reserved','settled')")
            other_total = sum(
                float(item.get("charge_usd") or 0.0)
                for item in active
                if item.get("reservation_id") != reservation_id
            )
            other_provider = sum(
                float(item.get("charge_usd") or 0.0)
                for item in active
                if item.get("reservation_id") != reservation_id
                and item.get("provider_id") == provider_id
            )
            other_cycle = sum(
                float(item.get("charge_usd") or 0.0)
                for item in active
                if item.get("reservation_id") != reservation_id and item.get("cycle_id") == cycle_id
            )
            over = bool(other_total + actual_usd > self.limits.global_usd)
            if self.limits.per_provider_usd:
                over = over or other_provider + actual_usd > self.limits.per_provider_usd
            if self.limits.per_cycle_usd:
                over = over or other_cycle + actual_usd > self.limits.per_cycle_usd
            settled = {
                **row,
                "actual_usd": actual_usd,
                "charge_usd": actual_usd,
                "status": "settled",
                "over_budget": over,
            }
            self.store.put(
                "budget_reservations",
                reservation_id,
                settled,
                extra={
                    "cycle_id": cycle_id,
                    "provider_id": provider_id,
                    "status": "settled",
                    "day": str(row.get("day") or ""),
                },
            )
            self._record(
                cycle_id,
                provider_id,
                actual_usd - estimate_usd,
                "commit",
                f"{reservation_id}:actual={actual_usd}:reserved={estimate_usd}:over={over}",
            )
        return (not over, "actual cost exceeded budget" if over else "settled")

    def release(
        self,
        *,
        cycle_id: str,
        provider_id: str,
        estimate_usd: float,
        reservation_id: str | None = None,
    ) -> None:
        if reservation_id is None:
            self._record(cycle_id, provider_id, -estimate_usd, "release", "legacy")
            return
        with self.store.transaction(immediate=True):
            row = self.store.get("budget_reservations", reservation_id)
            if row is None or row.get("status") != "reserved":
                raise ValueError("budget reservation not releasable")
            released = {**row, "charge_usd": 0.0, "status": "released"}
            self.store.put(
                "budget_reservations",
                reservation_id,
                released,
                extra={
                    "cycle_id": cycle_id,
                    "provider_id": provider_id,
                    "status": "released",
                    "day": str(row.get("day") or ""),
                },
            )
            self._record(cycle_id, provider_id, -estimate_usd, "release", reservation_id)

    def _record(
        self, cycle_id: str, provider_id: str, amount: float, kind: str, detail: str
    ) -> None:
        # budget_events is a record table keyed by a unique event id.
        self.store.put(
            "budget_events",
            f"be-{ulid()}",
            {
                "cycle_id": cycle_id,
                "provider_id": provider_id,
                "amount": amount,
                "kind": kind,
                "detail": detail,
            },
            extra={"cycle_id": cycle_id, "provider_id": provider_id},
        )
