"""Dynamic discovery + lazy, coverage-directed qualification (spec §10).

All configured providers are potential candidates unless excluded or unavailable.
Qualification is LAZY and coverage-directed: when a role has no eligible candidate,
identify currently-available unqualified candidates, apply the effective policy,
rank the CHEAPEST-to-qualify by metadata (never provider/catalogue order as a
quality signal), and qualify only enough to fill coverage + diversity — never the
whole catalogue.
"""

from __future__ import annotations

from .bootstrap import Candidate, policy_candidates
from .context import RuntimeContext
from .enums import InferenceMode
from .roster import _OPERATIONAL_ROLES
from .workforce import WorkforceSnapshot
from .workforce_policy import EffectiveWorkforcePolicy

# Cheapest-to-qualify first: local/free before subscription before paid. This is a
# genuine COST signal, not a provider preference.
_MODE_COST_RANK = {
    InferenceMode.LOCAL.value: 0,
    InferenceMode.FREE.value: 1,
    InferenceMode.SUBSCRIPTION.value: 2,
    InferenceMode.PAID.value: 3,
    "": 4,
}


def coverage_gaps(snapshot: WorkforceSnapshot) -> list[str]:
    """Operational roles with no eligible candidate in the current snapshot."""
    return [r.value for r in _OPERATIONAL_ROLES if snapshot.coverage.get(r.value, 0) == 0]


def rank_candidates_to_qualify(
    ctx: RuntimeContext,
    policy: EffectiveWorkforcePolicy,
    *,
    max_new: int | None = None,
) -> list[Candidate]:
    """Currently-available, policy-eligible, UNQUALIFIED candidates ranked cheapest
    first by metadata. Bounded by ``max_new`` (or policy.max_models_assessed).
    Provider/catalogue order is never a quality signal — cost rank + a deterministic
    id tie-break only."""
    from .selection import has_valid_evidence

    candidates, _excluded = policy_candidates(ctx, policy)
    unqualified = [c for c in candidates if not has_valid_evidence(ctx, c.provider_id, c.model_id)]
    unqualified.sort(key=lambda c: (_MODE_COST_RANK.get(c.mode, 4), c.provider_id, c.model_id))
    cap = max_new if max_new is not None else policy.max_models_assessed
    if cap is not None:
        unqualified = unqualified[:cap]
    return unqualified


def coverage_directed_candidates(
    ctx: RuntimeContext,
    policy: EffectiveWorkforcePolicy,
    snapshot: WorkforceSnapshot,
    *,
    max_new: int | None = None,
) -> tuple[list[Candidate], list[str]]:
    """Lazy plan: if the snapshot already covers every operational role, qualify
    NOTHING new (reuse valid evidence). Otherwise return a BOUNDED set of the
    cheapest unqualified candidates to close the gaps. Returns (candidates, gaps)."""
    gaps = coverage_gaps(snapshot)
    if not gaps:
        return [], []
    return rank_candidates_to_qualify(ctx, policy, max_new=max_new), gaps
