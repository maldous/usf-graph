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
from .capabilities import capabilities_for, role_transport_ok
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


def _admitted_for(
    ctx: RuntimeContext, role: AdmissionRole
) -> list[tuple[AgentProfile, dict[str, Any]]]:
    """Valid admitted (profile, decision) pairs for a role, deterministically
    ordered by profile_id (NOT storage order); transport must also be possible."""
    out: list[tuple[AgentProfile, dict[str, Any]]] = []
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, _run, reason = admission_ineligibility(ctx, profile)
        if reason is not None or decision is None:
            continue
        if role.value not in set(decision.get("roles", [])):
            continue
        cap = _profile_capabilities(ctx, profile)
        if not role_transport_ok(role, cap):
            continue
        out.append((profile, decision))
    return sorted(out, key=lambda t: t[0].profile_id)


def _profile_capabilities(ctx: RuntimeContext, profile: AgentProfile):
    from .providers import build_registry

    try:
        adapter = build_registry(ctx).adapter(profile.provider_id)
    except Exception:
        from .capabilities import AdapterCapabilities

        return AdapterCapabilities(plain_invoke=True, bounded_patch_synthesis=True)
    if hasattr(adapter, "capabilities"):
        return adapter.capabilities()
    return capabilities_for(adapter, ctx.config.providers.by_id().get(profile.provider_id))


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


def _config_digest(ctx: RuntimeContext) -> str:
    from .canonical import content_digest

    return content_digest({"providers": sorted(ctx.config.providers.by_id())})


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
    return ctx.store.get("role_rosters", _ACTIVE_KEY)


def roster_profile_for(ctx: RuntimeContext, role: AdmissionRole) -> AgentProfile | None:
    """The active roster's primary profile for a role, REVALIDATED at use
    (admission still valid, config matches). None => fall back to evidence scan."""
    r = active_roster(ctx)
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
        if reason is None:
            return profile
    return None
