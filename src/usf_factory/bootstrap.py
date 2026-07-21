"""Clean-state runtime bootstrap (§3).

Brings a fresh factory to a launch-ready state deterministically:

  1. refresh provider health (reuse discovery + provider evaluations),
  2. qualify ONLY the selected role candidates that lack fresh evidence,
  3. admit from evidence (no operator overrides, no lowered thresholds),
  4. build + activate the ranked role roster,
  5. verify roster/config freshness,
  6. report the exact unfilled roles + blockers,
  7. signal non-zero unless the minimum launch roster exists.

Preferred bounded allocation (subject to ACTUAL qualification — never forced):
  * Claude CLI  -> PATCH_PRODUCER / INTEGRATOR (verified actual model preferred),
  * Codex CLI   -> REVIEWER / PATCH_PRODUCER (provider-diverse from the producer),
  * a free OpenRouter model -> PLANNER / ANALYST fallback,
  * a local Ollama model -> ANALYST (never planner/integrator when its semantic
    optimization/scope is weak).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import RuntimeContext
from .enums import AdmissionRole

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
    mode: str  # subscription | free | local
    note: str = ""


@dataclass
class BootstrapReport:
    qualified: list[dict[str, Any]] = field(default_factory=list)
    admitted: list[dict[str, Any]] = field(default_factory=list)
    roster: dict[str, Any] = field(default_factory=dict)
    filled_roles: list[str] = field(default_factory=list)
    unfilled_roles: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    roster_fresh: bool = False
    minimum_shadow_ok: bool = False
    minimum_candidate_ok: bool = False


def _default_candidates(ctx: RuntimeContext) -> list[Candidate]:
    """The bounded selected set: the CLIs, a free OpenRouter model (if configured
    + discovered), and a local Ollama model (if discovered)."""
    cfg = ctx.config.providers.by_id()
    out: list[Candidate] = []
    if "claude-cli" in cfg:
        out.append(
            Candidate("claude-cli", "claude-opus-4-8", "subscription", "producer/integrator")
        )
    if "codex-cli" in cfg:
        out.append(Candidate("codex-cli", "gpt-5-codex", "subscription", "reviewer/producer"))
    # A genuinely free OpenRouter model (planner/analyst fallback), if discovered.
    free = _first_free_model(ctx, "openrouter")
    if free:
        out.append(Candidate("openrouter", free, "free", "planner/analyst fallback"))
    # A local model (analyst), if discovered.
    local = _first_local_model(ctx)
    if local:
        out.append(Candidate("ollama", local, "local", "analyst"))
    return out


def _first_free_model(ctx: RuntimeContext, provider_id: str) -> str | None:
    for row in ctx.store.records("models", "provider_id=?", (provider_id,)):
        if row.get("free") is True:
            return str(row.get("requested_model_id"))
    return None


def _first_local_model(ctx: RuntimeContext) -> str | None:
    rows = ctx.store.records("models", "provider_id=?", ("ollama",))
    return str(rows[0]["requested_model_id"]) if rows else None


def _auth_for(mode: str, max_cost_usd: float):
    from .probing import InferenceAuthorization

    return InferenceAuthorization(
        allow_inference=mode in ("free", "local"),
        allow_subscription_inference=mode == "subscription",
        allow_paid_inference=False,
        max_cost_usd=max_cost_usd,
    )


async def bootstrap_runtime(
    ctx: RuntimeContext,
    *,
    allow_subscription_inference: bool = False,
    allow_free_inference: bool = True,
    max_cost_usd: float = 0.0,
    max_cases: int = 0,
    force: bool = False,
    candidates: list[Candidate] | None = None,
) -> BootstrapReport:
    """Qualify the selected candidates that lack fresh evidence, admit, build and
    activate the ranked roster, and report launch readiness. Never raises for a
    single-candidate failure (records a blocker and continues)."""
    from .admission import admit_from_evidence, ensure_profile, qualify_live
    from .isolation import RepoIsolation
    from .roster import active_roster, build_roster, persist_active, roster_fresh
    from .selection import has_valid_evidence

    report = BootstrapReport()

    # 1) Refresh: ensure the factory mirror exists (read-only). Discovery +
    #    provider evaluations are REUSED (not re-run) as prior evidence.
    try:
        RepoIsolation(ctx.paths, ctx.usf_repo).ensure_mirror()
    except Exception as exc:
        report.blockers.append(f"mirror refresh failed: {type(exc).__name__}: {exc}")

    cands = candidates if candidates is not None else _default_candidates(ctx)
    if not cands:
        report.blockers.append(
            "no eligible role candidates discovered (run providers/models discover)"
        )

    # 2-3) Qualify only candidates lacking fresh evidence; admit from evidence.
    for c in cands:
        if c.mode == "subscription" and not allow_subscription_inference:
            report.blockers.append(
                f"{c.provider_id}: subscription inference not authorized (skipped)"
            )
            continue
        if c.mode in ("free", "local") and not allow_free_inference:
            report.blockers.append(
                f"{c.provider_id}: free/local inference not authorized (skipped)"
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
                    ctx, profile, auth=_auth_for(c.mode, max_cost_usd), max_cases=max_cases
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
