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

from .clock import utc_now, utc_now_iso
from .context import RuntimeContext
from .enums import AdmissionRole
from .errors import ConfigError
from .models import AgentProfile
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


def latest_qualification(ctx: RuntimeContext, profile_id: str) -> dict[str, Any] | None:
    rows = ctx.store.records("qualification_runs", "agent_profile_id=?", (profile_id,))
    return rows[-1] if rows else None


def admit_from_evidence(ctx: RuntimeContext, profile_id: str) -> list[AdmissionRole]:
    """Recompute admitted roles from STORED qualification evidence against the
    trust policy, stamp expiry, persist. No evidence => no admission."""
    run = latest_qualification(ctx, profile_id)
    if run is None:
        raise ConfigError(f"no qualification evidence for {profile_id}; run 'models qualify' first")
    roles = compute_admission_roles(dict(run.get("dimension_scores", {})), ctx.config.trust)
    expires = (utc_now() + timedelta(days=ctx.config.qualification.expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    run = dict(run)
    run["roles_admitted"] = [r.value for r in roles]
    run["admitted_at"] = utc_now_iso()
    ctx.store.put(
        "qualification_runs",
        profile_id,
        run,
        extra={"agent_profile_id": profile_id, "expires_at": expires},
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
    """Explicit OPERATOR grant of a single role, recorded as an override (an
    audited exception to evidence-computed admission, never the default path)."""
    run = latest_qualification(ctx, profile_id)
    if run is None:
        raise ConfigError(f"no qualification run exists for {profile_id} to attach a grant to")
    run = dict(run)
    roles = {AdmissionRole(r) for r in run.get("roles_admitted", [])}
    roles.add(role)
    run["roles_admitted"] = sorted(r.value for r in roles)
    run.setdefault("operator_overrides", []).append(
        {"role": role.value, "granted_at": utc_now_iso()}
    )
    ctx.store.put(
        "qualification_runs",
        profile_id,
        run,
        extra={"agent_profile_id": profile_id, "expires_at": run.get("expires_at", "")},
    )
    ctx.log_event(
        "admission.operator_override",
        stage="INIT",
        cycle_id="-",
        payload={"profile_id": profile_id, "role": role.value},
    )
    return sorted((AdmissionRole(r) for r in run["roles_admitted"]), key=lambda r: r.value)


def list_profiles(ctx: RuntimeContext) -> list[dict[str, Any]]:
    """Inventory of persisted profiles with their latest qualification facts."""
    out: list[dict[str, Any]] = []
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        run = latest_qualification(ctx, profile.profile_id)
        out.append(
            {
                "profile_id": profile.profile_id,
                "provider_id": profile.provider_id,
                "model": profile.requested_model_id,
                "adapter": profile.adapter,
                "roles": list(run.get("roles_admitted", [])) if run else [],
                "cases": f"{run.get('cases_passed', 0)}/{run.get('cases_total', 0)}"
                if run
                else "-",
                "qualified": run is not None,
            }
        )
    return sorted(out, key=lambda r: (r["provider_id"], r["model"]))


async def qualify_live(
    ctx: RuntimeContext,
    profile: AgentProfile,
    *,
    allow_billable: bool,
    budget_usd: float,
) -> Any:
    """Run the qualification suite against the LIVE model and persist the run.

    Gated: refuses without --allow-billable and a positive budget. A refusal
    persists NOTHING (a gated qualify never fabricates evidence)."""
    from pathlib import Path

    from .errors import ProtectedActionError
    from .qualification import build_run, collect_answers, load_corpus

    if not (allow_billable and budget_usd > 0):
        raise ProtectedActionError(
            "live qualification is billable: requires --allow-billable and --budget-usd > 0"
        )
    from .providers import build_registry

    # The adapter enforces its own billable gate as well (config-level), so an
    # operator must enable billing in BOTH places for a live call to happen.
    adapter = build_registry(ctx).adapter(profile.provider_id)
    suite = load_corpus(
        Path(ctx.config.qualification.corpus_dir), Path(ctx.config.qualification.holdout_dir)
    )

    async def _respond(case: Any) -> str:
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
        return resp.output_text

    answers = await collect_answers(suite, _respond)
    run = build_run(
        agent_profile_id=profile.profile_id,
        suite=suite,
        answers=answers,
        trust=ctx.config.trust,
        billable=True,
        expiry_days=ctx.config.qualification.expiry_days,
    )
    expires = (utc_now() + timedelta(days=ctx.config.qualification.expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ctx.store.put(
        "qualification_runs",
        profile.profile_id,
        run.content_dict(),
        extra={"agent_profile_id": profile.profile_id, "expires_at": expires},
    )
    return run
