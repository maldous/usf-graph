"""Dynamic dispatch (dynamic workforce spec §8/§9/§12/§13).

* §8 fallback: on a transient dispatch failure, record it, remove the candidate
  from the current attempt, and REDRAW from the remaining eligible population —
  preserving the same packet/authority binding, never repeating a committed side
  effect, never lowering a hard gate, bounded by a maximum attempt count.
* §9 reviewer/integrator independence: a reviewer is selected dynamically, is
  never the (or an) authoring provider, is family-diverse when required, and the
  wave BLOCKS rather than silently reusing an author.
* §12 routers: a router/opaque model may only mutate when its actual model is
  known, verified, and not excluded BEFORE source is sent.
* §13 continuous re-check: the active workforce snapshot is rebuilt when stale
  (policy/config/rule/TTL) before a wave/dispatch.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .adaptive_routing import (
    MODE_ADAPTIVE,
    adaptive_route,
    packet_eligibility,
    persist_routing_decision,
)
from .context import RuntimeContext
from .enums import TRANSIENT_DISPATCH_FAILURES, AdmissionRole, DispatchFailure
from .model_registry import canonical_family
from .models import Packet, RoutingDecision
from .workforce import (
    DEFAULT_TTL_S,
    WorkforceProfile,
    WorkforceSnapshot,
    active_workforce_snapshot,
    build_workforce_snapshot,
    persist_workforce_snapshot,
)
from .workforce_policy import EffectiveWorkforcePolicy

# invoke(profile) -> (ok, failure_class_or_None, result). The invoke callback is
# responsible for the side effect; the loop only redraws on failures that left NO
# committed side effect (transient), so a completed side effect is never repeated.
Invoke = Callable[[WorkforceProfile], "tuple[bool, DispatchFailure | None, Any]"]


@dataclass
class DispatchAttempt:
    profile_id: str
    ok: bool
    failure: str | None = None


@dataclass
class DispatchOutcome:
    packet_id: str
    role: str
    selected_profile_id: str | None
    ok: bool
    result: Any = None
    attempts: list[DispatchAttempt] = field(default_factory=list)
    decisions: list[RoutingDecision] = field(default_factory=list)
    blocked_reason: str = ""


def _record_failure(
    ctx: RuntimeContext, profile: WorkforceProfile, failure: DispatchFailure
) -> None:
    ctx.log_event(
        "dispatch.failure",
        stage="EXECUTING",
        payload={
            "profile_id": profile.profile_id,
            "provider_id": profile.provider_id,
            "failure": failure.value,
        },
    )


def dispatch_with_fallback(
    ctx: RuntimeContext,
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    packet: Packet,
    role: AdmissionRole,
    invoke: Invoke,
    *,
    mode: str = MODE_ADAPTIVE,
    max_attempts: int = 3,
    protected_allowed: bool = False,
    persist: bool = True,
) -> DispatchOutcome:
    """Route → invoke → (transient failure ⇒ remove candidate + redraw) up to
    ``max_attempts``, preserving the packet/authority binding. Blocks honestly when
    the eligible population is exhausted or a terminal (result-quality) failure
    occurs."""
    eligible, rejected = packet_eligibility(
        snapshot, policy, packet, role, protected_allowed=protected_allowed
    )
    outcome = DispatchOutcome(
        packet_id=packet.packet_id, role=role.value, selected_profile_id=None, ok=False
    )
    remaining = list(eligible)
    attempts = 0
    while remaining and attempts < max_attempts:
        decision = adaptive_route(
            remaining,
            rejected,
            packet,
            role,
            mode=mode,
            policy_digest=policy.digest(),
            snapshot_id=snapshot.snapshot_id,
        )
        if persist:
            persist_routing_decision(ctx, decision)
        outcome.decisions.append(decision)
        sel = decision.selected_profile_id
        if sel is None:
            break
        profile = next(p for p in remaining if p.profile_id == sel)
        attempts += 1
        ok, failure, result = invoke(profile)
        outcome.attempts.append(
            DispatchAttempt(sel, ok, failure.value if failure is not None else None)
        )
        if ok:
            outcome.ok = True
            outcome.selected_profile_id = sel
            outcome.result = result
            return outcome
        if failure is not None and failure in TRANSIENT_DISPATCH_FAILURES:
            _record_failure(ctx, profile, failure)
            remaining = [p for p in remaining if p.profile_id != sel]  # redraw pool
            continue
        # Terminal (result-quality) failure — never a silent redraw.
        outcome.selected_profile_id = sel
        outcome.blocked_reason = (
            f"terminal dispatch failure "
            f"{failure.value if failure is not None else 'UNKNOWN'} on {sel}"
        )
        return outcome
    if not outcome.blocked_reason:
        outcome.blocked_reason = (
            "no eligible candidate completed the packet after bounded redraws"
            if snapshot.role_candidates(role)
            else "no eligible candidate for role under policy"
        )
    return outcome


def _independent_candidates(
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    role: AdmissionRole,
    *,
    authoring_providers: set[str],
    authoring_families: set[str],
    need_family: bool,
) -> list[WorkforceProfile]:
    """Eligible candidates for an independence-constrained role (reviewer /
    integrator / adjudicator): not excluded, never an authoring provider, and
    family-diverse when required. No provider is preferred by name."""
    out: list[WorkforceProfile] = []
    for p in snapshot.role_candidates(role):
        if policy.candidate_exclusion(
            provider_id=p.provider_id,
            model_id=p.requested_model_id,
            adapter=p.adapter,
            inference_mode=p.inference_mode or None,
        ).excluded:
            continue
        if p.provider_id in authoring_providers:
            continue  # never reuse an authoring provider
        if (
            need_family
            and canonical_family(p.provider_id, p.requested_model_id) in authoring_families
        ):
            continue
        out.append(p)
    return out


def _reviewer_utility(profile: WorkforceProfile) -> float:
    """Reviewer/adjudicator judgement quality: defect detection + evidence
    discipline (fidelity), acceptance track record, and recent reliability. Kept
    bounded in [0,1]; token/latency efficiency is a minor tiebreak elsewhere."""
    reliability = 1.0 / (1.0 + float(max(0, profile.consecutive_failures)))
    return max(
        0.0,
        min(
            1.0,
            0.5 * profile.semantic_rule_fidelity
            + 0.3 * profile.accepted_success
            + 0.2 * reliability,
        ),
    )


def _adaptive_pick(candidates: list[WorkforceProfile], *, seed: str | None) -> WorkforceProfile:
    """Adaptive draw over independent candidates: a Beta-Bernoulli posterior over
    accepted/rejected trials blended with reviewer utility (no first-match bias)."""
    import random
    import secrets

    run_seed = seed or secrets.token_hex(16)
    rng = random.Random(run_seed)
    ordered = sorted(candidates, key=lambda p: p.profile_id)  # stable base order
    return max(
        ordered,
        key=lambda p: (
            rng.betavariate(1.0 + p.accepted_count, 1.0 + p.rejected_count)
            * (0.5 + 0.5 * _reviewer_utility(p))
        ),
    )


def select_reviewer(
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    *,
    authoring_providers: set[str],
    authoring_families: set[str] | None = None,
    require_family_diverse: bool | None = None,
    seed: str | None = None,
) -> tuple[WorkforceProfile | None, str]:
    """Select an independent reviewer via ADAPTIVE routing (not first-match): never
    an authoring provider, family-diverse when required, not excluded. Among the
    independent eligible reviewers the choice is an adaptive draw weighted by
    reviewer judgement utility. Blocks (None) rather than reusing an author."""
    need_family = (
        policy.require_family_diverse_review
        if require_family_diverse is None
        else require_family_diverse
    )
    eligible = _independent_candidates(
        snapshot,
        policy,
        AdmissionRole.REVIEWER,
        authoring_providers=authoring_providers,
        authoring_families=authoring_families or set(),
        need_family=need_family,
    )
    if not eligible:
        return None, (
            "no independent reviewer available (provider-diverse review required; "
            "an author is never silently reused)"
        )
    return _adaptive_pick(eligible, seed=seed), ""


def select_integrator(
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    *,
    authoring_providers: set[str],
    authoring_families: set[str] | None = None,
    require_family_diverse: bool | None = None,
    seed: str | None = None,
) -> tuple[WorkforceProfile | None, str]:
    """Select an AI integrator/adjudicator DYNAMICALLY for a semantic conflict that
    deterministic integration cannot resolve (spec §9). Provider/family-independent
    from the authors, not excluded, adaptive draw. No permanent integration
    provider: the choice is made per conflict from the current workforce. Blocks
    (None) when no independent qualified adjudicator exists."""
    need_family = (
        policy.require_family_diverse_review
        if require_family_diverse is None
        else require_family_diverse
    )
    authoring_families = authoring_families or set()
    # Prefer an ADJUDICATOR (conflict resolution); fall back to INTEGRATOR-tier.
    for role in (AdmissionRole.ADJUDICATOR, AdmissionRole.INTEGRATOR):
        eligible = _independent_candidates(
            snapshot,
            policy,
            role,
            authoring_providers=authoring_providers,
            authoring_families=authoring_families,
            need_family=need_family,
        )
        if eligible:
            return _adaptive_pick(eligible, seed=seed), ""
    return None, (
        "no independent qualified integrator/adjudicator available for semantic "
        "conflict resolution (an author is never reused; capability may be absent)"
    )


def router_ready_for_mutation(
    profile: WorkforceProfile, policy: EffectiveWorkforcePolicy
) -> tuple[bool, str]:
    """A router/opaque transport may mutate only when its ACTUAL model is known,
    verified (when required) and not excluded — established BEFORE source is sent."""
    if not profile.actual_model:
        return False, "router actual model unknown before dispatch"
    if policy.require_verified_actual_model_for_mutation and not profile.actual_model_verified:
        return False, "router actual model not verified"
    hit = policy.candidate_exclusion(
        provider_id=profile.provider_id,
        model_id=profile.requested_model_id,
        actual_model=profile.actual_model,
    )
    if hit.excluded:
        return False, f"actual routed model excluded: {hit.reason} (source={hit.source})"
    return True, ""


def refresh_active_workforce(
    ctx: RuntimeContext, policy: EffectiveWorkforcePolicy, *, ttl_s: int = DEFAULT_TTL_S
) -> WorkforceSnapshot:
    """Continuous re-check (§13): return the active snapshot if still fresh under
    the current policy/config; otherwise rebuild + persist a new one."""
    snap = active_workforce_snapshot(ctx, policy)
    if snap is not None:
        return snap
    snap = build_workforce_snapshot(ctx, policy, ttl_s=ttl_s)
    persist_workforce_snapshot(ctx, snap)
    return snap
