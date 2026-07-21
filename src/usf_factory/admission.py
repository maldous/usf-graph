"""Production model admission workflow (second review P1-7).

The operator path from a discovered model to a schedulable agent:

    models discover                    -> catalogue records
    models probe    <provider/model>   -> AgentProfile persisted (+ live probe, gated)
    models qualify  <provider/model>   -> QualificationRun from LIVE answers (gated)
    models admit    <profile-id>       -> roles recomputed from stored evidence
    models profiles                    -> inventory

Admission is COMPUTED from qualification evidence against the trust policy —
never asserted. An explicit operator grant exists but must be requested with
``--operator-override`` and is recorded as such. Live probing/qualification is
billable and stays gated; a gated run persists the PROFILE only, never
fabricated qualification evidence (reference-answer self-checks are not model
evidence and are never stored against a model).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .budget import BudgetLedger, BudgetLimits
from .clock import utc_now, utc_now_iso
from .context import RuntimeContext
from .enums import AdmissionRole
from .errors import ConfigError
from .ids import ulid
from .models import AdmissionDecision, AgentProfile
from .qualification import compute_admission_roles


def parse_model_ref(ref: str) -> tuple[str, str]:
    """Split 'provider/model' (model ids may themselves contain '/')."""
    if "/" not in ref:
        raise ConfigError(f"model reference must be provider/model, got '{ref}'")
    provider_id, model_id = ref.split("/", 1)
    if not provider_id or not model_id:
        raise ConfigError(f"model reference must be provider/model, got '{ref}'")
    return provider_id, model_id


def ensure_profile(ctx: RuntimeContext, provider_id: str, model_id: str) -> AgentProfile:
    """Create (or return) the persisted AgentProfile for provider/model. The
    adapter and auth mode come from the operator-maintained provider config —
    an unknown provider is a hard error, never a guessed profile."""
    cfg = ctx.config.providers.by_id().get(provider_id)
    if cfg is None:
        raise ConfigError(f"unknown provider '{provider_id}' (not in providers.yaml)")
    profile = AgentProfile(
        provider_id=provider_id,
        requested_model_id=model_id,
        adapter=cfg.adapter,
        auth_mode=cfg.auth_mode,
    )
    if ctx.store.get("agent_profiles", profile.profile_id) is None:
        ctx.store.put("agent_profiles", profile.profile_id, profile.content_dict())
        ctx.log_event(
            "admission.profile_created",
            stage="INIT",
            cycle_id="-",
            payload={"profile_id": profile.profile_id, "provider": provider_id, "model": model_id},
        )
    return profile


def _expiry(ctx: RuntimeContext, days: int | None = None) -> str:
    d = ctx.config.qualification.expiry_days if days is None else days
    return (utc_now() + timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_qualification(ctx: RuntimeContext, run: Any) -> str:
    """Persist a qualification run IMMUTABLY under its own run_id. Returns the id.

    Stored via ``model_dump`` (not ``content_dict``) so timestamps/expiry — which
    are volatile for content addressing — are preserved in this id-keyed record."""
    if not run.expires_at:
        run = run.model_copy(update={"expires_at": _expiry(ctx)})
    ctx.store.put(
        "qualification_runs",
        run.run_id,
        run.model_dump(mode="json"),
        extra={"agent_profile_id": run.agent_profile_id, "expires_at": run.expires_at},
    )
    return run.run_id


def latest_qualification(ctx: RuntimeContext, profile_id: str) -> dict[str, Any] | None:
    """Most recent qualification run for a profile (run_ids sort by time)."""
    rows = ctx.store.records("qualification_runs", "agent_profile_id=?", (profile_id,))
    if not rows:
        return None
    return sorted(rows, key=lambda r: r.get("ran_at", "") + r.get("run_id", ""))[-1]


def latest_admission(ctx: RuntimeContext, profile_id: str) -> dict[str, Any] | None:
    rows = ctx.store.records("admission_decisions", "agent_profile_id=?", (profile_id,))
    if not rows:
        return None
    return sorted(rows, key=lambda r: r.get("decided_at", "") + r.get("decision_id", ""))[-1]


def admit_from_evidence(ctx: RuntimeContext, profile_id: str) -> list[AdmissionRole]:
    """Compute admitted roles from the latest STORED qualification run against the
    trust policy and record a NEW immutable AdmissionDecision. The qualification
    evidence itself is never mutated. No evidence => no admission."""
    run = latest_qualification(ctx, profile_id)
    if run is None:
        raise ConfigError(f"no qualification evidence for {profile_id}; run 'models qualify' first")
    roles = compute_admission_roles(dict(run.get("dimension_scores", {})), ctx.config.trust)
    decision = AdmissionDecision(
        decision_id=f"adm-{ulid()}",
        agent_profile_id=profile_id,
        qualification_run_id=run.get("run_id", ""),
        roles=roles,
        method="evidence",
        config_digest=run.get("config_digest", ""),
        expires_at=run.get("expires_at", "") or _expiry(ctx),
        decided_at=utc_now_iso(),
    )
    ctx.store.put(
        "admission_decisions",
        decision.decision_id,
        decision.model_dump(mode="json"),
        extra={
            "agent_profile_id": profile_id,
            "qualification_run_id": decision.qualification_run_id,
        },
    )
    ctx.log_event(
        "admission.computed",
        stage="INIT",
        cycle_id="-",
        payload={"profile_id": profile_id, "roles": [r.value for r in roles]},
    )
    return roles


def grant_role_operator_override(
    ctx: RuntimeContext, profile_id: str, role: AdmissionRole
) -> list[AdmissionRole]:
    """Explicit OPERATOR grant, recorded as a NEW audited admission decision
    (never a mutation of qualification evidence). It carries forward the roles of
    the current admission plus the granted role."""
    current = latest_admission(ctx, profile_id)
    run = latest_qualification(ctx, profile_id)
    roles = {AdmissionRole(r) for r in (current.get("roles", []) if current else [])}
    roles.add(role)
    decision = AdmissionDecision(
        decision_id=f"adm-{ulid()}",
        agent_profile_id=profile_id,
        qualification_run_id=(run or {}).get("run_id", ""),
        roles=sorted(roles, key=lambda r: r.value),
        method="operator-override",
        config_digest=(run or {}).get("config_digest", ""),
        expires_at=_expiry(ctx),
        decided_at=utc_now_iso(),
        detail=f"operator granted {role.value}",
    )
    ctx.store.put(
        "admission_decisions",
        decision.decision_id,
        decision.model_dump(mode="json"),
        extra={
            "agent_profile_id": profile_id,
            "qualification_run_id": decision.qualification_run_id,
        },
    )
    ctx.log_event(
        "admission.operator_override",
        stage="INIT",
        cycle_id="-",
        payload={"profile_id": profile_id, "role": role.value},
    )
    return list(decision.roles)


def admission_ineligibility(
    ctx: RuntimeContext, profile: AgentProfile
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Return (decision, run, reason). ``reason`` is None iff this profile has a
    current admission decision referencing a valid qualification run whose
    configuration still matches the profile. The scheduler uses this to reject
    expired/superseded/mismatched qualification."""
    decision = latest_admission(ctx, profile.profile_id)
    if decision is None:
        return None, None, "no admission decision"
    run = ctx.store.get("qualification_runs", decision.get("qualification_run_id", ""))
    if run is None:
        return decision, None, "referenced qualification run missing"
    now = utc_now_iso()
    if decision.get("expires_at") and decision["expires_at"] < now:
        return decision, run, "admission expired"
    if run.get("expires_at") and run["expires_at"] < now:
        return decision, run, "qualification expired"
    # Superseded configuration: the profile's current digest must match the run.
    if run.get("config_digest") and run["config_digest"] != profile.digest():
        return decision, run, "configuration changed since qualification"
    return decision, run, None


def list_profiles(ctx: RuntimeContext) -> list[dict[str, Any]]:
    """Inventory of persisted profiles with their latest qualification/admission."""
    out: list[dict[str, Any]] = []
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        run = latest_qualification(ctx, profile.profile_id)
        decision = latest_admission(ctx, profile.profile_id)
        out.append(
            {
                "profile_id": profile.profile_id,
                "provider_id": profile.provider_id,
                "model": profile.requested_model_id,
                "adapter": profile.adapter,
                "roles": list(decision.get("roles", [])) if decision else [],
                "cases": f"{run.get('cases_passed', 0)}/{run.get('cases_total', 0)}"
                if run
                else "-",
                "qualified": run is not None,
                "admitted": decision is not None,
            }
        )
    return sorted(out, key=lambda r: (r["provider_id"], r["model"]))


async def qualify_live(
    ctx: RuntimeContext,
    profile: AgentProfile,
    *,
    auth: Any,
    probe_run_id: str = "",
) -> Any:
    """Run the qualification suite against the LIVE model and persist an immutable
    run. Inference is gated by the InferenceAuthorization and a budget
    reservation (same rules as probing). A refusal persists NOTHING."""
    from pathlib import Path

    from .errors import ProtectedActionError
    from .probing import _authorize, _est_cost, _model_row, classify_inference_mode
    from .providers import build_registry
    from .qualification import build_run, collect_answers, load_corpus

    model_row = _model_row(ctx, profile.provider_id, profile.requested_model_id)
    mode = classify_inference_mode(profile, model_row)
    est = _est_cost(model_row)
    ok, why = _authorize(mode, auth, est)
    if not ok:
        raise ProtectedActionError(f"live qualification not authorized ({mode}): {why}")

    ledger = BudgetLedger(ctx.store, BudgetLimits(global_usd=max(auth.max_cost_usd, 0.0)))
    reserved, rwhy = ledger.reserve(
        cycle_id="qualify", provider_id=profile.provider_id, estimate_usd=est
    )
    if not reserved:
        raise ProtectedActionError(f"qualification budget blocked: {rwhy}")

    adapter = build_registry(ctx, allow_billable=mode in ("subscription", "paid")).adapter(
        profile.provider_id
    )
    suite = load_corpus(
        Path(ctx.config.qualification.corpus_dir), Path(ctx.config.qualification.holdout_dir)
    )
    actual_models: set[str] = set()
    tokens_in = tokens_out = 0

    async def _respond(case: Any) -> str:
        nonlocal tokens_in, tokens_out
        from .models import AgentRequest

        resp = await adapter.invoke(
            AgentRequest(
                agent_profile_id=profile.profile_id,
                packet_id=f"qual:{case.case_id}",
                instructions=case.prompt,
                provider_id=profile.provider_id,
                requested_model_id=profile.requested_model_id,
                adapter_id=profile.adapter,
            )
        )
        if resp.actual_model:
            actual_models.add(resp.actual_model)
        tokens_in += resp.tokens_in or 0
        tokens_out += resp.tokens_out or 0
        return resp.output_text

    try:
        answers = await collect_answers(suite, _respond)
    finally:
        if est:
            ledger.commit(
                cycle_id="qualify",
                provider_id=profile.provider_id,
                estimate_usd=est,
                actual_usd=0.0,
            )

    run = build_run(
        agent_profile_id=profile.profile_id,
        suite=suite,
        answers=answers,
        trust=ctx.config.trust,
        billable=mode != "free",
        expiry_days=ctx.config.qualification.expiry_days,
        config_digest=profile.digest(),
        requested_model_id=profile.requested_model_id,
        prompt_version=profile.prompt_version,
        tool_profile=profile.tool_profile,
        holdout_digest=suite.suite_digest(),
        probe_run_id=probe_run_id,
        actual_models=sorted(actual_models),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=0.0 if mode == "free" else est,
    )
    record_qualification(ctx, run)  # immutable, keyed by run_id
    return run
