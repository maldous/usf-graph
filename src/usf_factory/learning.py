"""Attribution-driven learning (DESIGN Phase 14 / build task §17).

Updates task- and dimension-segmented scores AFTER deterministic qualification
and integration, using EWMA means with recency decay, minimum sample counts, and
confidence intervals. Workers are never penalized for non-worker faults.

Safety boundary: this engine may ONLY write ``model_task_scores`` (and routing
preferences derived from them). It never changes safety policy, egress policy,
trust tiers, credential access, publication gates, or source code — those are
reviewed changes only.
"""

from __future__ import annotations

import math

from .attribution import is_worker_fault
from .clock import utc_now_iso
from .enums import FailureClass
from .event_store import Store
from .models import ModelTaskScore

DEFAULT_DECAY = 0.85
DEFAULT_MIN_N = 5
Z_95 = 1.96


def score_key(agent_profile_id: str, task_class: str, dimension: str) -> str:
    return f"{agent_profile_id}|{task_class}|{dimension}"


def update_task_score(
    existing: ModelTaskScore | None,
    observation: float,
    *,
    agent_profile_id: str = "",
    task_class: str = "",
    dimension: str = "",
    decay: float = DEFAULT_DECAY,
    min_n: int = DEFAULT_MIN_N,
) -> ModelTaskScore:
    """Return an updated score with EWMA mean/variance and a confidence interval."""
    obs = max(0.0, min(1.0, observation))
    if existing is None:
        mean = obs
        var = 0.25  # prior variance (max for [0,1]) until we have samples
        n = 1
    else:
        n = existing.n + 1
        prev_mean = existing.mean
        mean = decay * prev_mean + (1 - decay) * obs
        # EWMA of squared deviation.
        dev = (obs - prev_mean) ** 2
        var = decay * existing.variance + (1 - decay) * dev
        agent_profile_id = agent_profile_id or existing.agent_profile_id
        task_class = task_class or existing.task_class
        dimension = dimension or existing.dimension

    if n < min_n:
        # Low confidence: widen the interval explicitly.
        ci_low = max(0.0, mean - 0.5)
        ci_high = min(1.0, mean + 0.5)
    else:
        half = Z_95 * math.sqrt(max(var, 1e-9) / n)
        ci_low = max(0.0, mean - half)
        ci_high = min(1.0, mean + half)

    return ModelTaskScore(
        agent_profile_id=agent_profile_id,
        task_class=task_class,
        dimension=dimension,
        mean=round(mean, 4),
        n=n,
        variance=round(var, 6),
        ci_low=round(ci_low, 4),
        ci_high=round(ci_high, 4),
        updated_at=utc_now_iso(),
    )


class LearningEngine:
    """Persists stage-specific scores. Touches only model_task_scores."""

    TABLE = "model_task_scores"

    def __init__(
        self, store: Store, *, decay: float = DEFAULT_DECAY, min_n: int = DEFAULT_MIN_N
    ) -> None:
        self.store = store
        self.decay = decay
        self.min_n = min_n

    def _get(self, key: str) -> ModelTaskScore | None:
        row = self.store.get(self.TABLE, key)
        return ModelTaskScore(**row) if row else None

    def record(
        self, agent_profile_id: str, task_class: str, dimension: str, observation: float
    ) -> ModelTaskScore:
        key = score_key(agent_profile_id, task_class, dimension)
        updated = update_task_score(
            self._get(key),
            observation,
            agent_profile_id=agent_profile_id,
            task_class=task_class,
            dimension=dimension,
            decay=self.decay,
            min_n=self.min_n,
        )
        self.store.put(
            self.TABLE,
            key,
            updated.content_dict(),
            extra={
                "agent_profile_id": agent_profile_id,
                "task_class": task_class,
                "dimension": dimension,
            },
        )
        return updated

    def record_worker_outcome(
        self,
        agent_profile_id: str,
        task_class: str,
        *,
        accepted: bool,
        failure_class: FailureClass | None,
        dimensions: tuple[str, ...] = ("implementation", "scope_discipline", "structured_output"),
    ) -> list[ModelTaskScore]:
        """Update worker scores after qualification. Non-worker faults are not
        counted against the worker (returns [])."""
        if failure_class is not None and not is_worker_fault(failure_class):
            return []  # do not penalize the worker for planner/provider/env faults
        obs = 1.0 if accepted else 0.0
        return [self.record(agent_profile_id, task_class, d, obs) for d in dimensions]

    def record_regression(
        self, agent_profile_id: str, task_class: str, regressed: bool
    ) -> ModelTaskScore:
        """Delayed feedback: later regression lowers the later_regression score."""
        return self.record(
            agent_profile_id, task_class, "later_regression", 0.0 if regressed else 1.0
        )

    def leaderboard(self, task_class: str, dimension: str) -> list[ModelTaskScore]:
        rows = self.store.records(
            self.TABLE, "task_class=? AND dimension=?", (task_class, dimension)
        )
        scores = [ModelTaskScore(**r) for r in rows]
        scores.sort(key=lambda s: (-s.mean, -s.n))
        return scores

    def scores_for(self, agent_profile_id: str, task_class: str) -> dict[str, float]:
        rows = self.store.records(
            self.TABLE, "agent_profile_id=? AND task_class=?", (agent_profile_id, task_class)
        )
        return {r["dimension"]: r["mean"] for r in rows}

    # ---- calibrated estimates from immutable raw observations (P1-20) ----- #

    def observe(
        self,
        stage: str,
        agent_profile_id: str,
        task_class: str,
        dimension: str,
        value: float,
        meta: dict | None = None,
    ) -> None:
        """Append an immutable raw observation. Score projections derive from these."""
        self.store.append(
            "observations",
            {"value": float(value), "meta": meta or {}},
            extra={
                "stage": stage,
                "agent_profile_id": agent_profile_id,
                "task_class": task_class,
                "dimension": dimension,
            },
        )

    def beta_estimate(
        self, agent_profile_id: str, task_class: str, dimension: str, *, z: float = Z_95
    ) -> tuple[float, float, float, int]:
        """Calibrated Beta-Bernoulli success estimate from raw observations.

        Returns (mean, ci_low, ci_high, n) using a Jeffreys Beta(0.5+s, 0.5+f)
        posterior mean and a normal approximation interval. Treats each
        observation >= 0.5 as a success.
        """
        rows = self.store.records(
            "observations",
            "stage='worker' AND agent_profile_id=? AND task_class=? AND dimension=?",
            (agent_profile_id, task_class, dimension),
        )
        vals = [float(r.get("value", 0.0)) for r in rows]
        n = len(vals)
        successes = sum(1 for v in vals if v >= 0.5)
        failures = n - successes
        a = 0.5 + successes
        b = 0.5 + failures
        mean = a / (a + b)
        var = (a * b) / (((a + b) ** 2) * (a + b + 1))
        half = z * math.sqrt(var)
        return (round(mean, 4), round(max(0.0, mean - half), 4), round(min(1.0, mean + half), 4), n)
