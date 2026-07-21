"""Budget reservation ledger (review §9.5).

Atomically reserve estimated cost before dispatch, then commit the actual cost or
release the reservation. Prevents overrun across global/provider/cycle scopes.
Backed by the append-only ``budget_events`` log so spend is auditable and
reconstructable. Local/free providers reserve 0.
"""

from __future__ import annotations

from dataclasses import dataclass

from .event_store import Store


@dataclass
class BudgetLimits:
    global_usd: float = 0.0
    per_provider_usd: float = 0.0
    per_cycle_usd: float = 0.0


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
        if estimate_usd <= 0:
            self._record(cycle_id, provider_id, 0.0, "reserve", "free/local")
            return True, "free"
        if self.limits.global_usd and self.spent_total() + estimate_usd > self.limits.global_usd:
            return False, "global budget exceeded"
        if (
            self.limits.per_provider_usd
            and self.spent_provider(provider_id) + estimate_usd > self.limits.per_provider_usd
        ):
            return False, f"provider {provider_id} budget exceeded"
        if (
            self.limits.per_cycle_usd
            and self.spent_cycle(cycle_id) + estimate_usd > self.limits.per_cycle_usd
        ):
            return False, "cycle budget exceeded"
        self._record(cycle_id, provider_id, estimate_usd, "reserve", "reserved")
        return True, "reserved"

    def commit(
        self, *, cycle_id: str, provider_id: str, estimate_usd: float, actual_usd: float
    ) -> None:
        # Record the delta between actual and reserved (release the difference).
        self._record(
            cycle_id,
            provider_id,
            actual_usd - estimate_usd,
            "commit",
            f"actual={actual_usd} reserved={estimate_usd}",
        )

    def release(self, *, cycle_id: str, provider_id: str, estimate_usd: float) -> None:
        self._record(cycle_id, provider_id, -estimate_usd, "release", "released reservation")

    def _record(
        self, cycle_id: str, provider_id: str, amount: float, kind: str, detail: str
    ) -> None:
        # budget_events is a record table keyed by a unique event id.
        from .ids import ulid

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
