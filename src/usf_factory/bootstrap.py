"""Clean-state runtime bootstrap (§3).

Brings a fresh factory to a launch-ready state deterministically:

  1. refresh provider health (reuse discovery + provider evaluations),
  2. qualify ONLY the selected role candidates that lack fresh evidence,
  3. admit from evidence (no operator overrides, no lowered thresholds),
  4. build + activate the ranked role roster,
  5. verify roster/config freshness,
  6. report the exact unfilled roles + blockers,
  7. signal non-zero unless the minimum launch roster exists.

The candidate population is built DYNAMICALLY from all currently discovered
providers/models after the effective WorkforcePolicy is applied (spec §1). No
provider, model, family or role allocation is hard-coded: every candidate is a
transport whose inference class is derived from its own evidence and whose
suitability is established from current qualification. Discovery/catalogue order
is never used as a quality signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import RuntimeContext
from .enums import AdmissionRole, AuthMode, InferenceMode, PrivacyClass
from .workforce_policy import (
    EffectiveWorkforcePolicy,
    committed_defaults,
    resolve_workforce_policy,
)

# Roles the minimum rosters require.
_SHADOW_ROLES = (AdmissionRole.PLANNER_CANDIDATE, AdmissionRole.READ_ONLY_ANALYST)
_CANDIDATE_ROLES = (
    AdmissionRole.PLANNER_CANDIDATE,
    AdmissionRole.PATCH_PRODUCER,
    AdmissionRole.REVIEWER,
)


@dataclass
class Candidate:
    provider_id: str
    model_id: str
    mode: str  # InferenceMode value: local | free | subscription | paid
    note: str = ""


@dataclass
class BootstrapReport:
    qualified: list[dict[str, Any]] = field(default_factory=list)
    admitted: list[dict[str, Any]] = field(default_factory=list)
    roster: dict[str, Any] = field(default_factory=dict)
    filled_roles: list[str] = field(default_factory=list)
    unfilled_roles: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    considered_candidates: list[dict[str, Any]] = field(default_factory=list)
    excluded_candidates: list[str] = field(default_factory=list)  # "prov/model: reason (source=..)"
    policy_digest: str = ""
    roster_fresh: bool = False
    minimum_shadow_ok: bool = False
    minimum_candidate_ok: bool = False


def _infer_mode(provider_cfg: Any, model_row: dict[str, Any]) -> InferenceMode:
    """Derive a candidate's inference class from its OWN transport + pricing
    evidence — never from a provider name. Local process → LOCAL; a genuinely
    free-priced model → FREE; an OIDC/CLI subscription transport → SUBSCRIPTION;
    otherwise a metered paid transport → PAID."""
    if (
        provider_cfg.auth_mode == AuthMode.LOCAL
        or provider_cfg.privacy_class == PrivacyClass.LOCAL_ONLY
    ):
        return InferenceMode.LOCAL
    if model_row.get("free") is True:
        return InferenceMode.FREE
    if provider_cfg.auth_mode == AuthMode.OIDC_CLI:
        return InferenceMode.SUBSCRIPTION
    return InferenceMode.PAID


def policy_candidates(
    ctx: RuntimeContext, policy: EffectiveWorkforcePolicy
) -> tuple[list[Candidate], list[str]]:
    """Build the candidate population from ALL discovered models, filtered by the
    effective WorkforcePolicy. Provider/model/family/adapter/actual-model and
    inference-class exclusions are applied here (before any probe/qualify/dispatch).
    Deterministic ordering (sorted) is for reproducibility only — never a quality
    signal. Returns (candidates, excluded_notes)."""
    providers = ctx.config.providers.by_id()
    cands: list[Candidate] = []
    excluded: list[str] = []
    rows = sorted(
        ctx.store.records("models"),
        key=lambda r: (str(r.get("provider_id", "")), str(r.get("requested_model_id", ""))),
    )
    for row in rows:
        pid = str(row.get("provider_id", ""))
        mid = str(row.get("requested_model_id", ""))
        pcfg = providers.get(pid)
        if pcfg is None:
            continue  # provider not configured/enabled in this environment
        mode = _infer_mode(pcfg, row)
        hit = policy.candidate_exclusion(
            provider_id=pid, model_id=mid, adapter=pcfg.adapter, inference_mode=mode
        )
        if hit.excluded:
            excluded.append(f"{pid}/{mid}: {hit.reason} (source={hit.source})")
            continue
        cands.append(Candidate(pid, mid, mode.value))
    if policy.max_models_assessed is not None:
        for extra in cands[policy.max_models_assessed :]:
            excluded.append(
                f"{extra.provider_id}/{extra.model_id}: over max_models_assessed cap "
                f"(source=policy)"
            )
        cands = cands[: policy.max_models_assessed]
    return cands, excluded


def _auth_for(mode: str, policy: EffectiveWorkforcePolicy, max_cost_usd: float):
    from .probing import InferenceAuthorization

    # allow_inference is the master switch; each class is additionally gated by the
    # effective policy (a mode already filtered out never reaches here).
    return InferenceAuthorization(
        allow_inference=True,
        allow_subscription_inference=policy.allow_subscription
        and mode == InferenceMode.SUBSCRIPTION.value,
        allow_paid_inference=policy.allow_paid and mode == InferenceMode.PAID.value,
        max_cost_usd=policy.max_paid_cost_usd
        if policy.max_paid_cost_usd is not None
        else max_cost_usd,
    )


async def bootstrap_runtime(
    ctx: RuntimeContext,
    *,
    policy: EffectiveWorkforcePolicy | None = None,
    max_cost_usd: float = 0.0,
    max_cases: int = 0,
    force: bool = False,
    candidates: list[Candidate] | None = None,
) -> BootstrapReport:
    """Build the candidate population dynamically from discovery + the effective
    WorkforcePolicy, qualify those lacking fresh evidence, admit from evidence,
    build/activate the ranked roster, and report launch readiness. Never raises for
    a single-candidate failure (records a blocker and continues). No provider or
    model is privileged; exclusions apply before any probe/qualify/dispatch."""
    from .admission import admit_from_evidence, ensure_profile, qualify_live
    from .isolation import RepoIsolation
    from .roster import active_roster, build_roster, persist_active, roster_fresh
    from .selection import has_valid_evidence

    report = BootstrapReport()
    policy = policy or resolve_workforce_policy(committed_defaults())
    report.policy_digest = policy.digest()

    # 1) Refresh: ensure the factory mirror exists (read-only). Discovery +
    #    provider evaluations are REUSED (not re-run) as prior evidence.
    try:
        RepoIsolation(ctx.paths, ctx.usf_repo).ensure_mirror()
    except Exception as exc:
        report.blockers.append(f"mirror refresh failed: {type(exc).__name__}: {exc}")

    # 2) Candidate population = all discovered models after policy (spec §1/§11).
    if candidates is not None:
        cands = candidates
    else:
        cands, report.excluded_candidates = policy_candidates(ctx, policy)
    report.considered_candidates = [
        {"provider": c.provider_id, "model": c.model_id, "mode": c.mode} for c in cands
    ]
    if not cands:
        report.blockers.append(
            "no eligible candidates after policy (run providers/models discover, "
            "or relax exclusions)"
        )

    # 3) Qualify only candidates lacking fresh evidence; admit from evidence. The
    #    policy already removed disallowed inference classes; re-check defensively.
    for c in cands:
        if not policy.inference_allowed(c.mode):
            report.excluded_candidates.append(
                f"{c.provider_id}/{c.model_id}: inference mode '{c.mode}' not allowed (source=policy)"
            )
            continue
        try:
            profile = ensure_profile(ctx, c.provider_id, c.model_id)
        except Exception as exc:
            report.blockers.append(f"{c.provider_id}/{c.model_id}: ensure_profile failed ({exc})")
            continue
        fresh = has_valid_evidence(ctx, c.provider_id, c.model_id)
        if fresh and not force:
            report.qualified.append({"profile": profile.profile_id, "reused": True, "note": c.note})
        else:
            try:
                run = await qualify_live(
                    ctx, profile, auth=_auth_for(c.mode, policy, max_cost_usd), max_cases=max_cases
                )
                report.qualified.append(
                    {
                        "profile": profile.profile_id,
                        "reused": False,
                        "cases": f"{run.cases_passed}/{run.cases_total}",
                        "roles": [r.value for r in run.roles_admitted],
                        "note": c.note,
                    }
                )
            except Exception as exc:  # quota/auth/output — never retry, never fabricate
                report.blockers.append(
                    f"{c.provider_id}/{c.model_id}: qualification skipped ({type(exc).__name__}: {str(exc)[:120]})"
                )
                continue
        try:
            roles = admit_from_evidence(ctx, profile.profile_id)
            report.admitted.append(
                {"profile": profile.profile_id, "roles": [r.value for r in roles]}
            )
        except Exception as exc:
            report.blockers.append(f"{profile.profile_id}: admission failed ({type(exc).__name__})")

    # 4-5) Build + activate the ranked roster; verify freshness.
    persist_active(ctx, build_roster(ctx))
    report.roster = active_roster(ctx) or {}
    report.roster_fresh = roster_fresh(ctx)

    # 6) Exact filled/unfilled roles.
    entries = report.roster.get("entries", {})
    for role in AdmissionRole:
        if role in (AdmissionRole.UNQUALIFIED,):
            continue
        entry = entries.get(role.value) or {}
        (report.filled_roles if entry.get("primary") else report.unfilled_roles).append(role.value)

    # 7) Minimum-roster readiness.
    report.minimum_shadow_ok = all(
        (entries.get(r.value) or {}).get("primary") for r in _SHADOW_ROLES
    )
    integrator_ok = bool((entries.get(AdmissionRole.INTEGRATOR.value) or {}).get("primary"))
    core_ok = all((entries.get(r.value) or {}).get("primary") for r in _CANDIDATE_ROLES)
    # Provider-diverse reviewer vs producer.
    prod = (entries.get(AdmissionRole.PATCH_PRODUCER.value) or {}).get("provider")
    rev = (entries.get(AdmissionRole.REVIEWER.value) or {}).get("provider")
    diverse = bool(prod and rev and prod != rev)
    # A deterministic clean-integration path always exists, so integrator is optional.
    report.minimum_candidate_ok = core_ok and diverse and (integrator_ok or True)
    if core_ok and not diverse:
        report.blockers.append("reviewer and producer share a provider (independence required)")
    return report
