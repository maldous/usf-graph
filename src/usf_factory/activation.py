"""Activation orchestration (Phase 13).

`usf-factory activate` drives the full readiness pipeline against real providers:
verify -> USF health/snapshot -> provider refresh + auth probes -> model
discovery -> mechanical probing -> bounded qualification -> evidence-based
admission -> live plan-only -> provider-diverse shadow wave -> optional one
candidate semantic packet -> independent review + validation -> activation report.

Default budget is 0 USD: local, genuinely free, or (opt-in) subscription/OIDC
providers only. Paid inference is NEVER a silent fallback. One provider being
quota-blocked or unavailable does not fail the whole activation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .admission import admit_from_evidence, ensure_profile, latest_admission
from .context import RuntimeContext
from .enums import AdmissionRole, AuthMode, RunMode
from .probing import InferenceAuthorization, probe_gates_pass, run_probe_suite


@dataclass
class ActivationOptions:
    free_only: bool = True
    allow_subscription_inference: bool = False
    allow_paid_inference: bool = False
    max_cost_usd: float = 0.0
    max_models_per_provider: int = 3
    shadow_packets: int = 1
    candidate_packet: bool = False


@dataclass
class ModelOutcome:
    provider_id: str
    model_id: str
    profile_id: str = ""
    classification: str = "READY"
    probe_passed: int = 0
    probe_total: int = 0
    roles: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class ActivationReport:
    usf_ok: bool = False
    authority_digest: str = ""
    snapshot_id: str = ""
    repository_head: str = ""
    triples: int | None = None
    providers_refreshed: dict[str, str] = field(default_factory=dict)
    model_outcomes: list[ModelOutcome] = field(default_factory=list)
    admitted: list[str] = field(default_factory=list)
    plan_only: dict[str, Any] = field(default_factory=dict)
    shadow: dict[str, Any] = field(default_factory=dict)
    candidate: dict[str, Any] = field(default_factory=dict)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    blockers: list[str] = field(default_factory=list)
    next_action: str = ""


def _auth_for(opts: ActivationOptions) -> InferenceAuthorization:
    return InferenceAuthorization(
        allow_inference=True,
        allow_subscription_inference=opts.allow_subscription_inference,
        allow_paid_inference=opts.allow_paid_inference,
        max_cost_usd=opts.max_cost_usd,
    )


def _candidate_models(ctx: RuntimeContext, opts: ActivationOptions) -> list[tuple[str, str]]:
    """Bounded shortlist of (provider, model) to probe: local + genuinely free,
    plus subscription CLIs when opted in. Paid models are excluded unless
    --allow-paid-inference. Capped per provider."""
    provs = ctx.config.providers.by_id()
    per_provider: dict[str, int] = {}
    out: list[tuple[str, str]] = []
    for row in ctx.store.records("models"):
        pid = row.get("provider_id", "")
        mid = row.get("requested_model_id", "")
        cfg = provs.get(pid)
        if not cfg or not mid:
            continue
        mode = _mode_for(cfg.auth_mode, row)
        if mode == "paid" and not opts.allow_paid_inference:
            continue
        if mode == "subscription" and not opts.allow_subscription_inference:
            continue
        if opts.free_only and mode != "free":
            continue
        if per_provider.get(pid, 0) >= opts.max_models_per_provider:
            continue
        per_provider[pid] = per_provider.get(pid, 0) + 1
        out.append((pid, mid))
    return out


def _mode_for(auth_mode: AuthMode, model_row: dict[str, Any]) -> str:
    if auth_mode == AuthMode.LOCAL:
        return "free"
    if auth_mode == AuthMode.OIDC_CLI:
        return "subscription"
    if model_row.get("free") is True:
        return "free"
    return "paid"


async def _refresh_and_discover(ctx: RuntimeContext, report: ActivationReport) -> None:
    from .clock import utc_now_iso
    from .enums import HealthStatus
    from .providers import build_registry

    reg = build_registry(ctx)
    ids = reg.enabled_ids()
    outcomes = await reg.discover_all(ids)
    for pid, o in outcomes.items():
        report.providers_refreshed[pid] = "ok" if o.ok else (o.error or "failed")[:60]
        ctx.store.put(
            "provider_health",
            pid,
            {
                "provider_id": pid,
                "status": (HealthStatus.HEALTHY if o.ok else HealthStatus.UNAVAILABLE).value,
                "detail": (o.error or "catalogue refreshed")[:200],
                "checked_at": utc_now_iso(),
            },
        )


def run_activation(ctx: RuntimeContext, opts: ActivationOptions) -> ActivationReport:
    """Synchronous entry point (drives async provider work internally)."""
    report = ActivationReport()

    # 2. USF health + snapshot.
    from .engine import FactoryEngine

    eng = FactoryEngine(ctx)
    try:
        with eng._authority_factory() as auth:
            h = auth.health().json()
        report.usf_ok = bool(h.get("ok"))
        report.triples = h.get("triples")
    except Exception as exc:
        report.blockers.append(f"USF health failed: {exc}")
    try:
        pre = eng.preflight("activate")
        if pre["cycleState"] == "BLOCKED":
            report.blockers.extend(pre["blockers"])
        snap = eng.capture_snapshot("activate")
        report.snapshot_id = snap.snapshot_id
        report.authority_digest = snap.authority_digest
        report.repository_head = snap.repository_head
    except Exception as exc:
        report.blockers.append(f"snapshot failed: {exc}")

    # 3-4. Provider refresh + discovery.
    try:
        asyncio.run(_refresh_and_discover(ctx, report))
    except Exception as exc:
        report.blockers.append(f"provider refresh failed: {exc}")

    # 5-7. Probe + qualify + admit a bounded shortlist. One provider failing is
    # isolated, never fatal.
    infer_auth = _auth_for(opts)
    for pid, mid in _candidate_models(ctx, opts):
        outcome = ModelOutcome(provider_id=pid, model_id=mid)
        try:
            profile = ensure_profile(ctx, pid, mid)
            outcome.profile_id = profile.profile_id
            probe = asyncio.run(run_probe_suite(ctx, profile, auth=infer_auth))
            outcome.probe_passed = probe.passed
            outcome.probe_total = probe.total
            report.tokens_in += probe.tokens_in
            report.tokens_out += probe.tokens_out
            report.cost_usd += probe.cost_usd
            if not probe_gates_pass(probe):
                outcome.classification = "FAILED_QUALIFICATION"
                outcome.detail = "structural probes failed"
            else:
                run = asyncio.run(_qualify(ctx, profile, infer_auth, probe.run_id))
                report.tokens_in += run.tokens_in
                report.tokens_out += run.tokens_out
                report.cost_usd += run.cost_usd
                roles = admit_from_evidence(ctx, profile.profile_id)
                outcome.roles = [r.value for r in roles]
                outcome.classification = _classify_roles(roles)
                if AdmissionRole.UNQUALIFIED not in roles:
                    report.admitted.append(profile.profile_id)
        except Exception as exc:
            outcome.classification = _classify_error(exc)
            outcome.detail = f"{type(exc).__name__}: {str(exc)[:120]}"
        report.model_outcomes.append(outcome)

    # 8. Live plan-only cycle (read-only; always safe).
    try:
        from .runtime import build_engine

        peng = build_engine(ctx, mode=RunMode.PLAN_ONLY)
        receipt = asyncio.run(peng.run_cycle(RunMode.PLAN_ONLY))
        report.plan_only = {
            "state": receipt.state.value,
            "selected": receipt.selected_packets,
            "blockers": receipt.blockers,
        }
    except Exception as exc:
        report.blockers.append(f"plan-only failed: {exc}")

    # 9. Provider-diverse shadow wave when an eligible analyst exists.
    report.shadow = _maybe_shadow(ctx, opts, report)

    # 10-11. Optional candidate packet (only if every prerequisite passes).
    if opts.candidate_packet:
        from .candidate import attempt_candidate_packet

        report.candidate = attempt_candidate_packet(ctx, opts)
    else:
        report.candidate = {"attempted": False, "reason": "not requested (--candidate-packet)"}

    report.next_action = _next_action(report)
    return report


async def _qualify(ctx: RuntimeContext, profile: Any, auth: Any, probe_run_id: str) -> Any:
    from .admission import qualify_live

    return await qualify_live(ctx, profile, auth=auth, probe_run_id=probe_run_id)


def _classify_roles(roles: list[AdmissionRole]) -> str:
    if AdmissionRole.INTEGRATOR in roles:
        return "QUALIFIED_INTEGRATOR"
    if AdmissionRole.REVIEWER in roles:
        return "QUALIFIED_REVIEWER"
    if AdmissionRole.PATCH_PRODUCER in roles:
        return "QUALIFIED_PATCH_PRODUCER"
    if AdmissionRole.PLANNER_CANDIDATE in roles:
        return "QUALIFIED_PLANNER"
    if AdmissionRole.READ_ONLY_ANALYST in roles:
        return "QUALIFIED_ANALYST"
    return "FAILED_QUALIFICATION"


def _classify_error(exc: Exception) -> str:
    msg = str(exc).lower()
    if "quota" in msg or "rate" in msg or "429" in msg:
        return "QUOTA_BLOCKED"
    if "auth" in msg or "401" in msg or "403" in msg or "credential" in msg:
        return "AUTH_FAILED"
    if "not authorized" in msg or "gated" in msg or "policy" in msg:
        return "POLICY_BLOCKED"
    if "connect" in msg or "timeout" in msg or "unavailable" in msg or "404" in msg:
        return "MODEL_UNAVAILABLE"
    return "FAILED_QUALIFICATION"


def _maybe_shadow(ctx: RuntimeContext, opts: ActivationOptions, report: ActivationReport) -> dict:
    """Run a shadow cycle if at least one admitted analyst exists (provider-diverse
    when two do). Shadow never mutates /usf."""
    from .models import AgentProfile
    from .runtime import build_engine

    analysts = []
    for _key, row in ctx.store.items("agent_profiles"):
        prof = AgentProfile(**row)
        dec = latest_admission(ctx, prof.profile_id)
        if dec and AdmissionRole.READ_ONLY_ANALYST.value in set(dec.get("roles", [])):
            analysts.append(prof)
    if not analysts:
        return {"ran": False, "reason": "no admitted analyst available"}
    providers = {p.provider_id for p in analysts}
    try:
        eng = build_engine(ctx, mode=RunMode.SHADOW)
        receipt = asyncio.run(eng.run_cycle(RunMode.SHADOW))
        return {
            "ran": True,
            "provider_diverse": len(providers) >= 2,
            "providers": sorted(providers),
            "state": receipt.state.value,
            "selected": receipt.selected_packets,
            "results": ctx.store.count("packet_results"),
            "blockers": receipt.blockers,
        }
    except Exception as exc:
        return {"ran": False, "reason": f"{type(exc).__name__}: {str(exc)[:120]}"}


def _next_action(report: ActivationReport) -> str:
    if not report.usf_ok:
        return "restore USF MCP authority connectivity"
    if not report.admitted:
        return (
            "no model admitted from real evidence — enable a suitable free/local model "
            "or opt into subscription inference, then re-run activate"
        )
    cand = report.candidate
    if cand.get("attempted") and cand.get("status") == "AWAITING_OPERATOR_DELIVERY":
        return "review the candidate patch and apply via the protected delivery process"
    if cand.get("attempted") and not cand.get("produced"):
        return f"candidate blocked: {cand.get('blocker', 'see report')}"
    return "run continuous shadow analysis to accumulate evidence-backed progress"
