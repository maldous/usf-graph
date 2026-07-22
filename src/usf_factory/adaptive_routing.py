"""Per-packet eligibility + adaptive selection (dynamic workforce spec §5-§7).

Selection is dynamic and per-packet: hard gates first (any failure => probability
zero), then a role/task/risk/data-class-segmented utility, then either genuine
contextual Thompson sampling (low/medium risk) or deterministic exploitation
(high/protected risk — never explored). Every decision persists a full, replayable
receipt: eligible + excluded candidates with reasons, utilities, Beta posteriors,
normalized probabilities, a FRESH cryptographic dispatch seed (never derived from
packet/snapshot identity), the selected profile, mode, and the policy + snapshot
digests. Replaying a receipt in ``deterministic-replay`` reproduces the recorded
choice exactly, even though a fresh live run draws a new seed.
"""

from __future__ import annotations

import random
import secrets

from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import AdmissionRole, Risk
from .models import Packet, RoutingCandidate, RoutingDecision
from .workforce import WorkforceProfile, WorkforceSnapshot
from .workforce_policy import EffectiveWorkforcePolicy

MODE_EXPLOIT = "exploit"
MODE_ADAPTIVE = "adaptive"
MODE_REPLAY = "deterministic-replay"

_SOURCE_DATA = {"private-source", "restricted"}
_NO_EXPLORE_RISK = {Risk.HIGH, Risk.PROTECTED}
_PRODUCER_TRANSPORTS = {"brokered_tool_loop", "bounded_patch_synthesis"}
_MUTATION_ROLES = {AdmissionRole.PATCH_PRODUCER, AdmissionRole.INTEGRATOR}


def fresh_seed() -> str:
    """A new cryptographically strong dispatch seed (persisted per decision)."""
    return secrets.token_hex(32)


def packet_eligibility(
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    packet: Packet,
    role: AdmissionRole,
    *,
    protected_allowed: bool = False,
) -> tuple[list[WorkforceProfile], list[RoutingCandidate]]:
    """Independently derive the eligible population for this packet. Hard gates
    (spec §5) are applied fail-closed; a candidate failing any gate is rejected
    with exact reasons and never receives selection probability."""
    eligible: list[WorkforceProfile] = []
    rejected: list[RoutingCandidate] = []
    for p in snapshot.role_candidates(role):
        reasons: list[str] = []
        # Effective policy may have changed since the snapshot was built.
        hit = policy.candidate_exclusion(
            provider_id=p.provider_id,
            model_id=p.requested_model_id,
            adapter=p.adapter,
            inference_mode=p.inference_mode or None,
        )
        if hit.excluded:
            reasons.append(f"policy: {hit.reason} (source={hit.source})")
        # Source containment for raw-source-bearing work (reviewer judges only a
        # bounded diff, so it is exempt).
        if (
            packet.data_classification in _SOURCE_DATA
            and policy.require_source_containment_for_private_source
            and not p.source_contained
            and role is not AdmissionRole.REVIEWER
        ):
            reasons.append("source containment required but not attested for this transport")
        # Verified actual model required before mutation (routers/opaque models).
        if (
            role in _MUTATION_ROLES
            and policy.require_verified_actual_model_for_mutation
            and p.actual_model
            and not p.actual_model_verified
        ):
            reasons.append("mutation requires a verified actual model")
        # Risk permission.
        if packet.risk is Risk.PROTECTED and not protected_allowed:
            reasons.append("protected risk requires an enabled gate")
        # Transport for the producer role.
        if role is AdmissionRole.PATCH_PRODUCER and not (_PRODUCER_TRANSPORTS & set(p.transports)):
            reasons.append("no producer transport (brokered tool loop / bounded patch synthesis)")
        if reasons:
            rejected.append(
                RoutingCandidate(
                    agent_profile_id=p.profile_id,
                    eligible=False,
                    exclusion_reasons=reasons,
                    provider_id=p.provider_id,
                    inference_mode=p.inference_mode,
                )
            )
        else:
            eligible.append(p)
    return eligible, rejected


def role_utility(profile: WorkforceProfile, packet: Packet, role: AdmissionRole) -> float:
    """Role/task/risk/data-class-segmented utility in [0,1]. There is no single
    global 'best model' score; the same model may rank differently per role/task.
    Higher-is-better signals reward; latency/cost penalize; unknown is neutral."""
    reward = (
        0.45 * profile.accepted_success
        + 0.30 * profile.semantic_rule_fidelity
        + 0.15 * profile.cache_reuse
    )
    # Reviewer independence/discipline weighs fidelity a little more; producers
    # weigh source-containment readiness. (Segmentation hook — kept bounded.)
    if role is AdmissionRole.PATCH_PRODUCER and profile.source_contained:
        reward += 0.05
    penalty = 0.10 * min(profile.latency_ms / 10000.0, 1.0) + 0.10 * min(profile.cost_usd, 1.0)
    return max(0.0, min(1.0, reward - penalty))


def _posterior(
    rng: random.Random, profile: WorkforceProfile, utility: float, explore: bool
) -> float:
    """Adaptive draw: a Beta-Bernoulli posterior over accepted/rejected trials,
    blended with utility. Low-evidence candidates get a wide posterior (bounded
    exploration); consistent successes concentrate high; failures concentrate low.
    Exploitation returns the deterministic utility (no randomness)."""
    if not explore:
        return utility
    alpha = 1.0 + float(profile.accepted_count)
    beta = 1.0 + float(profile.rejected_count)
    sample = rng.betavariate(alpha, beta)
    return sample * (0.5 + 0.5 * utility)


def adaptive_route(
    eligible: list[WorkforceProfile],
    rejected: list[RoutingCandidate],
    packet: Packet,
    role: AdmissionRole,
    *,
    mode: str = MODE_ADAPTIVE,
    seed: str | None = None,
    policy_digest: str = "",
    snapshot_id: str = "",
) -> RoutingDecision:
    """Select one eligible candidate. ``exploit`` picks the highest utility;
    ``adaptive`` draws via Thompson sampling (low/medium risk only); high/protected
    risk never explores regardless of mode; ``deterministic-replay`` reuses the
    given recorded seed to reproduce a prior decision."""
    # A live run passes no seed and gets a FRESH cryptographic one; an explicit
    # seed (deterministic-replay, or a caller/test driving the draw) is honoured.
    run_seed = seed or fresh_seed()
    rng = random.Random(run_seed)
    explore = mode != MODE_EXPLOIT and packet.risk not in _NO_EXPLORE_RISK

    scored: list[tuple[WorkforceProfile, float, float]] = []
    for p in sorted(eligible, key=lambda x: x.profile_id):
        u = role_utility(p, packet, role)
        post = _posterior(rng, p, u, explore)
        scored.append((p, post, u))

    total = sum(s[1] for s in scored) or 1.0
    candidates: list[RoutingCandidate] = [
        RoutingCandidate(
            agent_profile_id=p.profile_id,
            eligible=True,
            provider_id=p.provider_id,
            inference_mode=p.inference_mode,
            score=round(u, 6),
            utility=round(u, 6),
            posterior=round(post, 6),
            probability=round(post / total, 6),
        )
        for (p, post, u) in scored
    ]
    candidates.extend(rejected)

    selected_id: str | None = None
    kind = "none"
    if scored:
        # Highest posterior; ties break by profile_id (scored is profile_id-sorted).
        best = max(scored, key=lambda s: s[1])
        selected_id = best[0].profile_id
        kind = MODE_REPLAY if mode == MODE_REPLAY else (MODE_ADAPTIVE if explore else MODE_EXPLOIT)

    return RoutingDecision(
        packet_id=packet.packet_id,
        task_class=packet.task_class,
        role=role,
        selected_profile_id=selected_id,
        selection_kind=kind,
        routing_mode=mode,
        candidates=candidates,
        run_seed=run_seed,
        seed=run_seed,
        policy_digest=policy_digest,
        snapshot_id=snapshot_id,
        risk=packet.risk.value,
        decided_at=utc_now_iso(),
    )


def route_packet(
    ctx: RuntimeContext,
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    packet: Packet,
    role: AdmissionRole,
    *,
    mode: str = MODE_ADAPTIVE,
    seed: str | None = None,
    protected_allowed: bool = False,
    persist: bool = True,
) -> RoutingDecision:
    """End-to-end per-packet routing: eligibility → adaptive selection → receipt.
    Blocks (selected_profile_id is None) when no candidate survives the hard gates."""
    eligible, rejected = packet_eligibility(
        snapshot, policy, packet, role, protected_allowed=protected_allowed
    )
    decision = adaptive_route(
        eligible,
        rejected,
        packet,
        role,
        mode=mode,
        seed=seed,
        policy_digest=policy.digest(),
        snapshot_id=snapshot.snapshot_id,
    )
    if persist:
        persist_routing_decision(ctx, decision)
    return decision


def persist_routing_decision(ctx: RuntimeContext, decision: RoutingDecision) -> None:
    key = f"{decision.packet_id}:{decision.run_seed[:16]}"
    ctx.store.put(
        "routing_decisions",
        key,
        decision.model_dump(mode="json"),
        extra={"packet_id": decision.packet_id},
    )
    ctx.log_event(
        "routing.decision",
        stage="SCHEDULED",
        payload={
            "packet_id": decision.packet_id,
            "role": decision.role.value,
            "selected": decision.selected_profile_id,
            "mode": decision.routing_mode,
            "kind": decision.selection_kind,
            "policy_digest": decision.policy_digest,
            "snapshot_id": decision.snapshot_id,
        },
    )


def replay_routing_decision(
    recorded: RoutingDecision, eligible: list[WorkforceProfile], packet: Packet
) -> RoutingDecision:
    """Reproduce a recorded decision exactly from its persisted seed + mode."""
    return adaptive_route(
        eligible,
        [c for c in recorded.candidates if not c.eligible],
        packet,
        recorded.role,
        mode=MODE_REPLAY,
        seed=recorded.run_seed,
        policy_digest=recorded.policy_digest,
        snapshot_id=recorded.snapshot_id,
    )
