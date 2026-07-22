"""Active role roster (final completion pass §8).

Builds a content-addressed RoleRoster from ADMITTED profiles (evidence-based,
ranked deterministically — never storage-iteration order), persists it, and lets
the production runtime consume it for planner/analyst/producer/reviewer/
integrator selection with reviewer independence. Dispatch-time revalidation
(admission validity, config match, transport) still applies at use.
"""

from __future__ import annotations

from typing import Any

from .admission import admission_ineligibility
from .capabilities import role_transport_ok
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import AdmissionRole
from .ids import ulid
from .models import AgentProfile, RoleRoster

_ACTIVE_KEY = "active"

_OPERATIONAL_ROLES = (
    AdmissionRole.PLANNER_CANDIDATE,
    AdmissionRole.READ_ONLY_ANALYST,
    AdmissionRole.PATCH_PRODUCER,
    AdmissionRole.REVIEWER,
    AdmissionRole.INTEGRATOR,
)


def _semantic_scores(ctx: RuntimeContext, provider_id: str) -> dict[str, float]:
    """Per-provider semantic scores from the latest provider evaluation."""
    try:
        rows = ctx.store.records("provider_evaluations", "provider_id=?", (provider_id,))
    except Exception:
        return {}
    latest = None
    for row in rows:
        if latest is None or row.get("evaluated_at", "") > latest.get("evaluated_at", ""):
            latest = row
    return dict((latest or {}).get("semantic_scores") or {})


def _profile_metrics(ctx: RuntimeContext, profile_id: str) -> dict[str, float]:
    """Aggregated per-profile runtime metrics (accepted-packet success, uncached
    input per accepted packet, cache reuse, latency, cost). Empty when unproven —
    unknown is neutral, never fabricated."""
    try:
        rows = ctx.store.records("profile_metrics", "agent_profile_id=?", (profile_id,))
    except Exception:
        rows = []
    if not rows:
        return {}
    accepted = sum(int(r.get("accepted") or 0) for r in rows)
    rejected = sum(int(r.get("rejected") or 0) for r in rows)
    uncached = sum(float(r.get("uncached_input_tokens") or 0) for r in rows)
    cached = sum(float(r.get("cached_input_tokens") or 0) for r in rows)
    latency = [float(v) for r in rows if (v := r.get("latency_ms")) is not None]
    cost = sum(float(r.get("cost_usd") or 0) for r in rows)
    total = accepted + rejected
    total_in = uncached + cached
    return {
        "accepted_success": (accepted / total) if total else 0.0,
        "uncached_per_accepted": (uncached / accepted) if accepted else 0.0,
        "cache_reuse": (cached / total_in) if total_in else 0.0,
        "latency_ms": (sum(latency) / len(latency)) if latency else 0.0,
        "cost_usd": cost,
    }


def _rank_key(
    ctx: RuntimeContext,
    profile: AgentProfile,
    run: dict[str, Any] | None,
    role: AdmissionRole | None = None,
    cap: Any = None,
) -> tuple[Any, ...]:
    """Lexicographic ranking key (best first when sorted ascending). Order:
    (producer-only) source-containment, qualification score, semantic-rule
    fidelity, semantic optimization, scope discipline, evidence discipline,
    accepted-packet success, lowest uncached input/accepted, highest cache reuse,
    latency, cost, then profile_id tie-break. Higher-is-better fields are negated;
    lower-is-better kept; unknown is neutral."""
    run = run or {}
    dims = run.get("dimension_scores", {}) or {}
    ct = int(run.get("cases_total") or 0)
    qual = (int(run.get("cases_passed") or 0) / ct) if ct else 0.0
    sem = _semantic_scores(ctx, profile.provider_id)
    m = _profile_metrics(ctx, profile.profile_id)
    # Roles that RECEIVE the source context pack (produce/analyse/integrate source)
    # must prefer a source-contained provider; an uncontained provider (e.g. Codex)
    # can only receive metadata. The reviewer is exempt (it judges a bounded diff,
    # which the spec explicitly permits for Codex). Leading key; neutral otherwise.
    _SOURCE_ROLES = (
        AdmissionRole.PATCH_PRODUCER,
        AdmissionRole.READ_ONLY_ANALYST,
        AdmissionRole.INTEGRATOR,
    )
    contained_pref = 0
    if role in _SOURCE_ROLES and cap is not None:
        contained_pref = 0 if getattr(cap, "source_contained", False) else 1
    return (
        contained_pref,
        -qual,
        -float(sem.get("semantic_rule_fidelity", 0.0)),
        -float(sem.get("semantic_optimization", 0.0)),
        -float(dims.get("scope_discipline", 0.0)),
        -float(dims.get("evidence_discipline", 0.0)),
        -float(m.get("accepted_success", 0.0)),
        float(m.get("uncached_per_accepted", 0.0)),
        -float(m.get("cache_reuse", 0.0)),
        float(m.get("latency_ms", 0.0)),
        float(m.get("cost_usd", 0.0)),
        profile.profile_id,  # deterministic final tie-break ONLY
    )


def _admitted_for(
    ctx: RuntimeContext, role: AdmissionRole
) -> list[tuple[AgentProfile, dict[str, Any]]]:
    """Valid admitted (profile, decision) pairs for a role, ranked by semantic
    quality and token efficiency (profile_id is the final tie-break ONLY);
    transport must also be possible. For PATCH_PRODUCER, source-contained
    providers rank first."""
    out: list[tuple[AgentProfile, dict[str, Any], tuple[Any, ...]]] = []
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, run, reason = admission_ineligibility(ctx, profile)
        if reason is not None or decision is None:
            continue
        if role.value not in set(decision.get("roles", [])):
            continue
        cap = _profile_capabilities(ctx, profile)
        if not role_transport_ok(role, cap):
            continue
        out.append((profile, decision, _rank_key(ctx, profile, run, role, cap)))
    out.sort(key=lambda t: t[2])
    return [(p, d) for p, d, _k in out]


def _profile_capabilities(ctx: RuntimeContext, profile: AgentProfile):
    from .capabilities import UNAVAILABLE, capabilities_for_kind, observed_capabilities

    # Transport capability is a property of the adapter KIND (its class), derived
    # credential-free from the real implementation — never an adapter-name set. An
    # unknown/unbuildable adapter kind grants NO capability (ineligible).
    cap = capabilities_for_kind(profile.adapter)
    if cap is UNAVAILABLE:
        return UNAVAILABLE
    return cap.with_observed(observed_capabilities(ctx, profile.provider_id))


def build_roster(ctx: RuntimeContext, evaluation_run_id: str = "") -> RoleRoster:
    """Assemble the roster from current admission evidence + transport capability.
    Reviewer prefers a provider different from producer/integrator."""
    entries: dict[str, Any] = {}
    picked_providers: set[str] = set()
    # Fill non-reviewer roles first so reviewer can prefer a different provider.
    order = [
        AdmissionRole.PLANNER_CANDIDATE,
        AdmissionRole.READ_ONLY_ANALYST,
        AdmissionRole.PATCH_PRODUCER,
        AdmissionRole.INTEGRATOR,
        AdmissionRole.REVIEWER,
    ]
    for role in order:
        cands = _admitted_for(ctx, role)
        if role == AdmissionRole.REVIEWER:
            diverse = [c for c in cands if c[0].provider_id not in picked_providers]
            ranked = diverse + [c for c in cands if c[0].provider_id in picked_providers]
            independence = "unavailable" if not diverse and cands else "ok"
        else:
            ranked = cands
            independence = None
        if not ranked:
            entries[role.value] = {"primary": None, "fallbacks": [], "status": "NO_QUALIFIED_MODEL"}
            continue
        primary, decision = ranked[0]
        cap = _profile_capabilities(ctx, primary)
        entry = {
            "primary": primary.profile_id,
            "provider": primary.provider_id,
            "requested_model": primary.requested_model_id,
            "transport": (
                "brokered_tool_loop" if cap.brokered_tool_loop else "bounded_patch_synthesis"
            )
            if role == AdmissionRole.PATCH_PRODUCER
            else "plain_invoke",
            "qualification_run_id": decision.get("qualification_run_id", ""),
            "fallbacks": [p.profile_id for p, _d in ranked[1:4]],
        }
        if independence is not None:
            entry["reviewer_independence"] = independence
        entries[role.value] = entry
        if role in (AdmissionRole.PATCH_PRODUCER, AdmissionRole.INTEGRATOR):
            picked_providers.add(primary.provider_id)

    roster = RoleRoster(
        evaluation_run_id=evaluation_run_id,
        config_digest=_config_digest(ctx),
        rule_bundle_digest=_rule_digest(),
        entries=entries,
        created_at=utc_now_iso(),
    )
    return roster.model_copy(update={"roster_id": f"roster-{ulid()}"})


def _suite_digests(ctx: RuntimeContext) -> list[list[str]]:
    try:
        rows = [r for _k, r in ctx.store.items("qualification_suites")]
    except Exception:
        return []
    return sorted(
        [str(r.get("suite_id", "")), str(r.get("version", "")), str(r.get("suite_digest", ""))]
        for r in rows
    )


def runtime_config_digest(ctx: RuntimeContext) -> str:
    """Digest of the FULL relevant configuration the roster is bound to: provider
    config, trust policy, routing policy, egress policy, task classes, qualification
    suite/version, and the semantic rule-bundle digest. A roster is stale (rejected
    at use) once any of these change."""
    from .canonical import content_digest

    cfg = ctx.config
    return content_digest(
        {
            "providers": {
                pid: c.model_dump(mode="json") for pid, c in cfg.providers.by_id().items()
            },
            "trust": cfg.trust.model_dump(mode="json"),
            "routing": cfg.routing.model_dump(mode="json"),
            "egress": cfg.egress.model_dump(mode="json"),
            "task_classes": {
                n: t.model_dump(mode="json") for n, t in cfg.task_classes.by_name().items()
            },
            "qualification_suites": _suite_digests(ctx),
            "rule_bundle": _rule_digest(),
        }
    )


def _config_digest(ctx: RuntimeContext) -> str:
    return runtime_config_digest(ctx)


def _rule_digest() -> str:
    from .provider_eval import rule_bundle_digest

    return rule_bundle_digest()


def persist_active(ctx: RuntimeContext, roster: RoleRoster) -> RoleRoster:
    """Persist the roster by id AND set it as the ACTIVE roster the runtime reads."""
    payload = roster.model_dump(mode="json")
    ctx.store.put("role_rosters", roster.roster_id, payload)
    ctx.store.put("role_rosters", _ACTIVE_KEY, {**payload, "roster_id": roster.roster_id})
    ctx.log_event(
        "roster.activated",
        stage="INIT",
        cycle_id="-",
        payload={"roster_id": roster.roster_id, "roles": list(roster.entries)},
    )
    return roster


def active_roster(ctx: RuntimeContext) -> dict[str, Any] | None:
    """The ACTIVE roster, or None. A roster whose bound digests no longer match
    the current configuration is STALE and is not returned (fail closed)."""
    r = ctx.store.get("role_rosters", _ACTIVE_KEY)
    if not r:
        return None
    if (
        r.get("config_digest") != _config_digest(ctx)
        or r.get("rule_bundle_digest") != _rule_digest()
    ):
        ctx.log_event(
            "roster.stale",
            stage="INIT",
            cycle_id="-",
            payload={
                "roster_id": r.get("roster_id"),
                "reason": "config or rule-bundle digest changed",
            },
        )
        return None
    return r


def roster_fresh(ctx: RuntimeContext) -> bool:
    """True iff an active roster exists and its bound digests still match."""
    return active_roster(ctx) is not None


def roster_profile_for(ctx: RuntimeContext, role: AdmissionRole) -> AgentProfile | None:
    """The active roster's primary profile for a role, REVALIDATED at use
    (admission still valid, config+rule digests match, transport still possible).
    None => fall back to evidence scan."""
    r = active_roster(ctx)  # already rejects a stale roster
    if not r:
        return None
    entry = (r.get("entries") or {}).get(role.value) or {}
    pid = entry.get("primary")
    if not pid:
        return None
    for candidate_pid in [pid, *entry.get("fallbacks", [])]:
        row = ctx.store.get("agent_profiles", candidate_pid)
        if not row:
            continue
        profile = AgentProfile(**row)
        _d, _run, reason = admission_ineligibility(ctx, profile)
        if reason is not None:
            continue
        if not role_transport_ok(role, _profile_capabilities(ctx, profile)):
            continue
        return profile
    return None
