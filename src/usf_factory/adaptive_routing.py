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
            actual_model=p.actual_model,
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
            and p.is_router
            and policy.require_verified_actual_model_for_mutation
            and (not p.actual_model or not p.actual_model_verified)
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


# Uncertainty prior for a candidate with NO accepted/rejected evidence yet: a
# modest, explicitly-uncertain baseline that supports bounded exploration —
# NEVER treated as proven excellence (spec §5). The Beta-Bernoulli posterior in
# ``_posterior`` supplies the actual exploration width; this only sets where an
# evidence-free candidate's utility sits relative to a proven one.
_UNKNOWN_PRIOR = 0.4

_SEMANTIC_TASK_HINTS = (
    "semantic",
    "sparql",
    "shacl",
    "authority",
    "proof",
    "planning",
    "rdf",
    "owl",
)
_PRODUCER_TRANSPORTS = {"brokered_tool_loop", "bounded_patch_synthesis"}
_SOURCE_DATA_CLASSES = {"private-source", "restricted"}


def _evidence_confidence(profile: WorkforceProfile) -> float:
    """How much runtime evidence backs this profile's success signals, in [0,1].
    Zero for a brand-new candidate (=> lean on the uncertainty prior)."""
    trials = profile.accepted_count + profile.rejected_count
    if trials <= 0:
        return 0.0
    return min(1.0, trials / 8.0)


def role_utility(profile: WorkforceProfile, packet: Packet, role: AdmissionRole) -> float:
    """Role/task/risk/data-class/transport-SEGMENTED utility in [0,1].

    There is no single global 'best model' score: the reward mix is chosen per
    role and shifted by task class, risk, data classification and transport, so
    the same model can rank highly for one role and poorly for another. Proven
    higher-is-better signals reward; latency/cost/saturation penalize; unproven
    evidence is blended toward an explicit uncertainty prior (never excellence).
    """
    task = (packet.task_class or "").lower()
    semantic_task = any(h in task for h in _SEMANTIC_TASK_HINTS)
    high_risk = packet.risk in (Risk.HIGH, Risk.PROTECTED)
    source_data = packet.data_classification in _SOURCE_DATA_CLASSES

    # --- component signals (each in [0,1]) --------------------------------- #
    accepted = profile.accepted_success  # task-class accepted-result rate proxy
    fidelity = profile.semantic_rule_fidelity  # semantic/RDF/SHACL validation proxy
    qualification = min(1.0, profile.qualification_score)  # role qualification LCB proxy
    cache = profile.cache_reuse
    reliability = 1.0 / (1.0 + float(max(0, profile.consecutive_failures)))  # circuit/saturation

    # --- role-segmented reward mix ----------------------------------------- #
    if role is AdmissionRole.PATCH_PRODUCER:
        # Bounded-patch success + reasoning fidelity; transport + containment matter.
        reward = 0.42 * accepted + 0.24 * fidelity + 0.14 * qualification + 0.10 * cache
        if _PRODUCER_TRANSPORTS & set(profile.transports):
            reward += 0.06
        if profile.source_contained and source_data:
            reward += 0.04
    elif role is AdmissionRole.REVIEWER:
        # Defect detection + evidence discipline (fidelity), independence handled
        # by the reviewer gate; efficiency matters less than judgement.
        reward = 0.45 * fidelity + 0.30 * accepted + 0.15 * qualification + 0.05 * cache
    elif role in (AdmissionRole.INTEGRATOR, AdmissionRole.ADJUDICATOR):
        # Semantic adjudication: reasoning fidelity + proven acceptance.
        reward = 0.40 * fidelity + 0.34 * accepted + 0.20 * qualification
    elif role is AdmissionRole.PLANNER_CANDIDATE:
        reward = 0.40 * fidelity + 0.30 * qualification + 0.24 * accepted
    else:  # READ_ONLY_ANALYST and any other read role
        reward = 0.40 * accepted + 0.25 * fidelity + 0.20 * qualification + 0.15 * cache

    # --- task/risk/data shifts --------------------------------------------- #
    if semantic_task:
        # Semantic work leans harder on rule fidelity.
        reward = 0.85 * reward + 0.15 * fidelity
    if high_risk:
        # High/protected risk rewards demonstrated reliability, discounts novelty.
        reward = 0.80 * reward + 0.20 * (accepted * reliability)

    # --- uncertainty prior ------------------------------------------------- #
    # A candidate may only exceed the uncertainty prior to the extent it has real
    # trial evidence: unproven "excellence" is discounted toward the prior, so a
    # brand-new candidate is never ranked as proven-excellent (spec §5). Bounded
    # exploration itself is supplied by the Beta-Bernoulli posterior downstream.
    conf = _evidence_confidence(profile)
    if reward > _UNKNOWN_PRIOR:
        reward = _UNKNOWN_PRIOR + conf * (reward - _UNKNOWN_PRIOR)

    # --- penalties (segmented) --------------------------------------------- #
    penalty = 0.10 * min(profile.latency_ms / 10000.0, 1.0) + 0.12 * min(profile.cost_usd, 1.0)
    penalty += 0.08 * min(profile.uncached_per_accepted, 1.0)
    penalty += 0.10 * (1.0 - reliability)  # saturation / repeated recent failure
    if high_risk:
        penalty *= 1.25  # high-risk work is less tolerant of cost/latency/instability

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
