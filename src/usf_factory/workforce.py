"""Dynamic evidence-based WorkforceSnapshot (dynamic workforce spec §4).

Replaces the fixed-primary role roster with a bounded cache of ALL currently
eligible profiles and their evidence. Role views are GENERATED from the snapshot
for reporting; actual per-packet selection happens at dispatch time (spec 5-7). A
snapshot is stale (never used) once its TTL elapses OR the effective policy,
runtime configuration (providers/trust/routing/egress/task-classes/qualification
suite/rule bundle), or bound digests change. No provider is stored under a fixed
role key as a permanent primary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import AdmissionRole
from .model_registry import is_router_alias
from .models import AgentProfile, FactoryModel, stable_id
from .roster import (
    _OPERATIONAL_ROLES,
    _admitted_for,
    _profile_capabilities,
    _profile_metrics,
    _rule_digest,
    _semantic_scores,
    runtime_config_digest,
)
from .workforce_policy import EffectiveWorkforcePolicy

DEFAULT_TTL_S = 300


class WorkforceProfile(FactoryModel):
    """A currently-eligible transport with its current evidence (spec §4)."""

    profile_id: str
    provider_id: str
    requested_model_id: str
    actual_model: str = ""
    actual_model_verified: bool = False
    is_router: bool = False
    adapter: str = ""
    inference_mode: str = ""
    privacy_class: str = ""
    source_contained: bool = False
    transports: list[str] = Field(default_factory=list)
    admitted_roles: list[str] = Field(default_factory=list)
    qualification_score: float = 0.0
    semantic_rule_fidelity: float = 0.0
    accepted_success: float = 0.0
    accepted_count: int = 0
    rejected_count: int = 0
    uncached_per_accepted: float = 0.0
    cache_reuse: float = 0.0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    health: str = "unknown"
    evidence_fresh: bool = True
    consecutive_failures: int = 0


class WorkforceSnapshot(FactoryModel):
    """A bounded cache of current facts — not a permanent assignment."""

    policy_digest: str
    config_digest: str
    rule_bundle_digest: str
    ttl_s: int = DEFAULT_TTL_S
    profiles: list[WorkforceProfile] = Field(default_factory=list)
    # role -> ranked profile_ids (a generated VIEW, never a stored fixed primary)
    role_order: dict[str, list[str]] = Field(default_factory=dict)
    coverage: dict[str, int] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    excluded: list[str] = Field(default_factory=list)
    built_at: str = ""

    _volatile_fields = frozenset({"built_at"})

    @property
    def snapshot_id(self) -> str:
        return stable_id("wf", self.content_dict())

    def by_id(self) -> dict[str, WorkforceProfile]:
        return {p.profile_id: p for p in self.profiles}

    def role_candidates(self, role: AdmissionRole) -> list[WorkforceProfile]:
        """The ranked eligible profiles for a role — generated from the snapshot,
        never a stored primary. Selection still happens per-packet at dispatch."""
        index = self.by_id()
        return [index[pid] for pid in self.role_order.get(role.value, []) if pid in index]


def _mode_for(ctx: RuntimeContext, provider_cfg: Any, provider_id: str, model_id: str) -> str:
    from .bootstrap import _infer_mode

    row: dict[str, Any] = {}
    for r in ctx.store.records("models", "provider_id=?", (provider_id,)):
        if str(r.get("requested_model_id")) == model_id:
            row = r
            break
    return _infer_mode(provider_cfg, row).value


def _build_profile(
    ctx: RuntimeContext, profile: AgentProfile, roles: list[str]
) -> WorkforceProfile:
    cap = _profile_capabilities(ctx, profile)
    metrics = _profile_metrics(ctx, profile.profile_id)
    sem = _semantic_scores(ctx, profile.provider_id)
    try:
        metric_rows = ctx.store.records(
            "profile_metrics", "agent_profile_id=?", (profile.profile_id,)
        )
    except Exception:
        metric_rows = []
    accepted_count = sum(int(r.get("accepted") or 0) for r in metric_rows)
    rejected_count = sum(int(r.get("rejected") or 0) for r in metric_rows)
    try:
        qualification_rows = ctx.store.records(
            "qualification_runs", "agent_profile_id=?", (profile.profile_id,)
        )
    except Exception:
        qualification_rows = []
    latest_qualification = max(
        qualification_rows,
        key=lambda row: str(row.get("ran_at") or "") + str(row.get("run_id") or ""),
        default={},
    )
    actual_models = sorted(
        {
            str(value)
            for value in latest_qualification.get("actual_models", [])
            if isinstance(value, str) and value
        }
    )
    actual_model = actual_models[0] if len(actual_models) == 1 else ""
    providers = ctx.config.providers.by_id()
    pcfg = providers.get(profile.provider_id)
    transports = ["plain_invoke"]
    if getattr(cap, "brokered_tool_loop", False):
        transports.append("brokered_tool_loop")
    if getattr(cap, "bounded_patch_synthesis", False):
        transports.append("bounded_patch_synthesis")
    return WorkforceProfile(
        profile_id=profile.profile_id,
        provider_id=profile.provider_id,
        requested_model_id=profile.requested_model_id,
        actual_model=actual_model,
        actual_model_verified=bool(actual_model),
        is_router=is_router_alias(profile.provider_id, profile.requested_model_id),
        adapter=profile.adapter,
        inference_mode=_mode_for(ctx, pcfg, profile.provider_id, profile.requested_model_id)
        if pcfg
        else "",
        privacy_class=pcfg.privacy_class.value if pcfg else "",
        source_contained=bool(getattr(cap, "source_contained", False)),
        transports=transports,
        admitted_roles=sorted(roles),
        semantic_rule_fidelity=float(sem.get("semantic_rule_fidelity", 0.0)),
        accepted_success=float(metrics.get("accepted_success", 0.0)),
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        uncached_per_accepted=float(metrics.get("uncached_per_accepted", 0.0)),
        cache_reuse=float(metrics.get("cache_reuse", 0.0)),
        latency_ms=float(metrics.get("latency_ms", 0.0)),
        cost_usd=float(metrics.get("cost_usd", 0.0)),
    )


def build_workforce_snapshot(
    ctx: RuntimeContext, policy: EffectiveWorkforcePolicy, *, ttl_s: int = DEFAULT_TTL_S
) -> WorkforceSnapshot:
    """Assemble the current eligible workforce from admission evidence + transport
    capability, filtered by the effective policy. Every operational role gets a
    ranked view; nothing is privileged by name."""
    providers = ctx.config.providers.by_id()
    profiles: dict[str, WorkforceProfile] = {}
    roles_of: dict[str, set[str]] = {}
    role_order: dict[str, list[str]] = {}
    coverage: dict[str, int] = {}
    blockers: list[str] = []
    excluded: list[str] = []

    for role in _OPERATIONAL_ROLES:
        ordered: list[str] = []
        for profile, _decision in _admitted_for(ctx, role):
            pcfg = providers.get(profile.provider_id)
            mode = (
                _mode_for(ctx, pcfg, profile.provider_id, profile.requested_model_id)
                if pcfg
                else ""
            )
            hit = policy.candidate_exclusion(
                provider_id=profile.provider_id,
                model_id=profile.requested_model_id,
                adapter=profile.adapter,
                inference_mode=mode or None,
            )
            if hit.excluded:
                note = f"{profile.provider_id}/{profile.requested_model_id}: {hit.reason} (source={hit.source})"
                if note not in excluded:
                    excluded.append(note)
                continue
            ordered.append(profile.profile_id)
            roles_of.setdefault(profile.profile_id, set()).add(role.value)
            if profile.profile_id not in profiles:
                profiles[profile.profile_id] = profile  # type: ignore[assignment]
        role_order[role.value] = ordered
        coverage[role.value] = len(ordered)
        if not ordered:
            blockers.append(f"role '{role.value}' has no eligible candidate under policy")

    built = {
        pid: _build_profile(ctx, prof, sorted(roles_of.get(pid, set())))  # type: ignore[arg-type]
        for pid, prof in profiles.items()
    }
    return WorkforceSnapshot(
        policy_digest=policy.digest(),
        config_digest=runtime_config_digest(ctx),
        rule_bundle_digest=_rule_digest(),
        ttl_s=ttl_s,
        profiles=sorted(built.values(), key=lambda p: p.profile_id),
        role_order=role_order,
        coverage=coverage,
        blockers=blockers,
        excluded=excluded,
        built_at=utc_now_iso(),
    )


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def workforce_stale(
    ctx: RuntimeContext,
    snapshot: WorkforceSnapshot,
    policy: EffectiveWorkforcePolicy,
    *,
    now: str | None = None,
) -> tuple[bool, str]:
    """Fail-closed staleness. A snapshot is stale on ANY of: TTL elapsed, effective
    policy digest changed, runtime config digest changed, or rule-bundle changed."""
    if snapshot.policy_digest != policy.digest():
        return True, "effective WorkforcePolicy changed"
    if snapshot.config_digest != runtime_config_digest(ctx):
        return True, "runtime configuration changed"
    if snapshot.rule_bundle_digest != _rule_digest():
        return True, "semantic rule bundle changed"
    built = _parse_iso(snapshot.built_at)
    current = _parse_iso(now or utc_now_iso())
    if (
        built is not None
        and current is not None
        and (current - built).total_seconds() > snapshot.ttl_s
    ):
        return True, "snapshot TTL elapsed"
    return False, ""


def persist_workforce_snapshot(
    ctx: RuntimeContext, snapshot: WorkforceSnapshot
) -> WorkforceSnapshot:
    payload = snapshot.model_dump(mode="json")
    ctx.store.put("workforce_snapshots", snapshot.snapshot_id, payload)
    ctx.store.put("workforce_snapshots", "active", {**payload, "_active_id": snapshot.snapshot_id})
    ctx.log_event(
        "workforce.snapshot",
        stage="INIT",
        cycle_id="-",
        payload={
            "snapshot_id": snapshot.snapshot_id,
            "coverage": snapshot.coverage,
            "policy_digest": snapshot.policy_digest,
        },
    )
    return snapshot


def active_workforce_snapshot(
    ctx: RuntimeContext, policy: EffectiveWorkforcePolicy, *, now: str | None = None
) -> WorkforceSnapshot | None:
    """The ACTIVE snapshot if present and NOT stale; else None (fail closed)."""
    row = ctx.store.get("workforce_snapshots", "active")
    if not row:
        return None
    row = {k: v for k, v in row.items() if k != "_active_id"}
    snap = WorkforceSnapshot.model_validate(row)
    stale, reason = workforce_stale(ctx, snap, policy, now=now)
    if stale:
        ctx.log_event(
            "workforce.stale",
            stage="INIT",
            cycle_id="-",
            payload={"snapshot_id": snap.snapshot_id, "reason": reason},
        )
        return None
    return snap
