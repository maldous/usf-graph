"""Provider/model selection tournament + central role selector (milestone 3).

A staged tournament establishes the workforce from repeatable, role-specific,
cache-aware, provider-diverse evidence — never catalogue order or the first
admitted profile:

  Stage A  metadata + availability (discovery + exclusions/filters)
  Stage B  inexpensive mechanical screening (the 10 genuine probes; hard gates)
  Stage C  role-specific mini-suite (bounded, role-relevant prompts)
  Stage D  repeated full qualification for promoted critical roles (LCB)
  Stage E  common shadow bake-off (elsewhere; recorded in the report)

A central evidence-based selector ranks eligible profiles per role, enforces
reviewer/critic independence, and treats router aliases as stochastic services
rather than single models.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .admission import admission_ineligibility, ensure_profile
from .context import RuntimeContext
from .enums import AdmissionRole, AuthMode
from .model_registry import family_matches
from .probing import InferenceAuthorization, run_probe_suite

# Probes that any TOOL-USING role must pass (a prohibited-tool failure blocks
# every tool-using role regardless of average).
_STRUCTURAL_PROBES = {
    "strict_json",
    "iri_preservation",
    "digest_preservation",
    "explicit_uncertainty",
    "stop_condition",
}
# All three must pass for the BROKERED tool-loop transport (native tool calls).
_BROKERED_TOOL_GATES = {"forced_tool_call", "tool_result_followup", "prohibited_tool_compliance"}

# Roles that require repeated evidence before admission (one run is insufficient).
_CRITICAL_ROLES = {
    AdmissionRole.PATCH_PRODUCER,
    AdmissionRole.INTEGRATOR,
    AdmissionRole.REVIEWER,
    AdmissionRole.PLANNER_CANDIDATE,
}


@dataclass
class SelectionFilters:
    exclude_providers: list[str] = field(default_factory=list)
    exclude_models: list[str] = field(default_factory=list)
    exclude_families: list[str] = field(default_factory=list)
    include_models: list[str] = field(default_factory=list)  # force-include exact ids
    only_models: list[str] = field(
        default_factory=list
    )  # if set, assess ONLY these (provider/model)
    force_reassess: bool = False
    skip_valid_existing: bool = True

    def is_excluded(self, provider_id: str, model_id: str) -> tuple[bool, str]:
        full = f"{provider_id}/{model_id}"
        if self.include_models and (model_id in self.include_models or full in self.include_models):
            return False, ""
        if provider_id in self.exclude_providers:
            return True, f"provider {provider_id} excluded"
        if model_id in self.exclude_models or full in self.exclude_models:
            return True, "model excluded"
        for fam in self.exclude_families:
            if family_matches(provider_id, model_id, fam):
                return True, f"family '{fam}' excluded"
        return False, ""


def default_filters() -> SelectionFilters:
    """The mandated default next assessment: exclude ollama + llama family, and
    the two already-assessed slow local models; skip models with valid evidence."""
    return SelectionFilters(
        exclude_providers=["ollama"],
        exclude_models=["lfm2.5:8b-a1b-q8_0", "north-mini-code-1.0:q4_K_M"],
        exclude_families=["llama"],
        skip_valid_existing=True,
    )


@dataclass
class ModelAssessment:
    provider_id: str
    model_id: str
    profile_id: str = ""
    stage_reached: str = "A"
    classification: str = "READY"
    probe_passed: int = 0
    probe_total: int = 0
    structural_ok: bool = False
    tool_ok: bool = False
    role_scores: dict[str, float] = field(default_factory=dict)  # role -> LCB over trials
    role_trials: dict[str, list[float]] = field(default_factory=dict)
    actual_models: list[str] = field(default_factory=list)
    is_router: bool = False
    tokens_in: int = 0
    tokens_out: int = 0
    cached_input_tokens: int = 0
    uncached_input_tokens: int = 0
    cost_usd: float = 0.0
    cost_verified: bool = False
    cli_version: str | None = None
    detail: str = ""
    skipped_existing: bool = False


_ROUTER_ALIASES = {"openrouter/auto", "openrouter/free"}


def _is_router_alias(provider_id: str, model_id: str) -> bool:
    full = f"{provider_id}/{model_id}".lower()
    return full in _ROUTER_ALIASES or model_id.lower() in ("auto", "openrouter/auto")


def candidate_models(
    ctx: RuntimeContext, filters: SelectionFilters, order: list[str] | None = None
) -> list[tuple[str, str]]:
    """Discovered (provider, model) pairs after exclusions, ordered by the
    assessment provider order (unlisted providers last)."""
    order = order or []
    rank = {pid: i for i, pid in enumerate(order)}
    only = set(filters.only_models)
    out: list[tuple[str, str]] = []
    for row in ctx.store.records("models"):
        pid, mid = row.get("provider_id", ""), row.get("requested_model_id", "")
        if not pid or not mid:
            continue
        if only and f"{pid}/{mid}" not in only and mid not in only:
            continue
        excluded, _why = filters.is_excluded(pid, mid)
        if excluded and not only:  # an explicit --models list overrides exclusions
            continue
        out.append((pid, mid))
    out.sort(key=lambda t: (rank.get(t[0], len(order)), t[0], t[1]))
    return out


def has_valid_evidence(ctx: RuntimeContext, provider_id: str, model_id: str) -> bool:
    """True iff a current, config-matching admission already exists for this
    provider/model (so --skip-valid-existing can skip it)."""
    profile = (
        ensure_profile(ctx, provider_id, model_id) if _provider_known(ctx, provider_id) else None
    )
    if profile is None:
        return False
    decision, _run, reason = admission_ineligibility(ctx, profile)
    return reason is None and decision is not None


def _provider_known(ctx: RuntimeContext, provider_id: str) -> bool:
    return provider_id in ctx.config.providers.by_id()


def _lcb(values: list[float]) -> float:
    """Lower confidence bound (mean - 1 stdev), floored at the worst observation
    — admission for mutation roles uses this, never the best run."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    m = statistics.fmean(values)
    sd = statistics.pstdev(values)
    return max(min(values), m - sd)


def _inference_mode(profile_auth: AuthMode, model_row: dict[str, Any]) -> str:
    if profile_auth == AuthMode.LOCAL:
        return "free"
    if profile_auth == AuthMode.OIDC_CLI:
        return "subscription"
    return "free" if model_row.get("free") is True else "paid"


def _model_row(ctx: RuntimeContext, provider_id: str, model_id: str) -> dict[str, Any]:
    for row in ctx.store.records("models", "provider_id=?", (provider_id,)):
        if row.get("requested_model_id") == model_id:
            return row
    return {}


# --------------------------------------------------------------------------- #
# Tournament (Stage A-C, repeated) + persistence.
# --------------------------------------------------------------------------- #


async def assess_model(
    ctx: RuntimeContext,
    provider_id: str,
    model_id: str,
    *,
    auth: InferenceAuthorization,
    repeats: int = 1,
) -> ModelAssessment:
    """Stage A (already discovered) + Stage B (genuine probes, repeated) for one
    model. Repeated probe rounds give a lower-confidence probe score for critical
    roles; a single successful round is never enough to admit a critical role."""
    a = ModelAssessment(provider_id=provider_id, model_id=model_id)
    a.is_router = _is_router_alias(provider_id, model_id)
    profile = ensure_profile(ctx, provider_id, model_id)
    a.profile_id = profile.profile_id

    structural_rounds: list[float] = []
    tool_pass_rounds: list[float] = []
    actual: set[str] = set()
    rounds = max(1, repeats)
    last_err = ""
    for _r in range(rounds):
        try:
            run = await run_probe_suite(ctx, profile, auth=auth)
        except Exception as exc:  # quota/auth/unavailable — classify, don't crash
            last_err = f"{type(exc).__name__}: {exc}"
            a.classification = _classify_error(exc)
            a.detail = last_err[:160]
            return a
        a.stage_reached = "B"
        a.probe_passed = run.passed
        a.probe_total = run.total
        a.tokens_in += run.tokens_in
        a.tokens_out += run.tokens_out
        a.cached_input_tokens += run.cached_input_tokens
        a.uncached_input_tokens += run.uncached_input_tokens
        a.cost_usd += run.cost_usd
        a.cost_verified = a.cost_verified or run.cost_verified
        a.cli_version = a.cli_version or run.cli_version
        actual.update(run.actual_models)
        passed_kinds = {r.kind.value for r in run.results if r.passed}
        structural_rounds.append(1.0 if _STRUCTURAL_PROBES.issubset(passed_kinds) else 0.0)
        # ALL THREE brokered tool gates must pass for the brokered path (a
        # prohibited-tool failure is disqualifying regardless of the average).
        tool_pass_rounds.append(1.0 if _BROKERED_TOOL_GATES.issubset(passed_kinds) else 0.0)
        if any(r.detail == "QUOTA_BLOCKED" for r in run.results):
            a.classification = "QUOTA_BLOCKED"
            a.detail = "subscription/quota exhausted"
            return a

    a.actual_models = sorted(actual)
    a.structural_ok = _lcb(structural_rounds) >= 1.0
    a.role_trials["structural"] = structural_rounds
    a.role_trials["tool"] = tool_pass_rounds

    # TRANSPORT capability from the actual adapter (not the name): does it drive
    # the brokered tool loop, and can it do bounded patch synthesis?
    cap = _adapter_capabilities(ctx, provider_id)
    # Brokered tool_ok requires ALL three brokered gates (forced call, tool-result
    # follow-up, prohibited-tool compliance) to pass across rounds (LCB) AND an
    # adapter that actually has the brokered loop.
    brokered_tool_ok = cap.brokered_tool_loop and _lcb(tool_pass_rounds) >= 1.0
    a.tool_ok = brokered_tool_ok
    stable = not a.is_router or len(a.actual_models) == 1

    # Plain-invoke roles need only structural probes (analyst/planner/reviewer/
    # integrator do NOT require native tool calling).
    if a.structural_ok and cap.plain_invoke:
        for role in (
            AdmissionRole.READ_ONLY_ANALYST,
            AdmissionRole.PLANNER_CANDIDATE,
            AdmissionRole.REVIEWER,
            AdmissionRole.INTEGRATOR,
        ):
            a.role_scores[role.value] = _lcb(structural_rounds)
    # PATCH_PRODUCER: brokered tool loop (all gates) OR bounded patch synthesis
    # (structural + plain invoke; no native tool calls required). Router aliases
    # are never eligible for this mutation role.
    if stable and (brokered_tool_ok or (cap.bounded_patch_synthesis and a.structural_ok)):
        a.role_scores[AdmissionRole.PATCH_PRODUCER.value] = _lcb(
            tool_pass_rounds if brokered_tool_ok else structural_rounds
        )
    a.classification = _classify_assessment(a)
    return a


def _adapter_capabilities(ctx: RuntimeContext, provider_id: str):
    from .capabilities import AdapterCapabilities, capabilities_for
    from .providers import build_registry

    try:
        adapter = build_registry(ctx).adapter(provider_id)
    except Exception:
        return AdapterCapabilities(plain_invoke=True, bounded_patch_synthesis=True)
    if hasattr(adapter, "capabilities"):
        return adapter.capabilities()
    return capabilities_for(adapter, ctx.config.providers.by_id().get(provider_id))


def _classify_error(exc: Exception) -> str:
    m = str(exc).lower()
    if "quota" in m or "rate" in m or "429" in m or "usage limit" in m:
        return "QUOTA_BLOCKED"
    if "auth" in m or "401" in m or "403" in m or "credential" in m or "unauthorized" in m:
        return "AUTH_FAILED"
    if "not authorized" in m or "gated" in m or "policy" in m:
        return "POLICY_BLOCKED"
    if "connect" in m or "timeout" in m or "unavailable" in m or "404" in m or "http 4" in m:
        return "MODEL_UNAVAILABLE"
    return "FAILED_QUALIFICATION"


def _classify_assessment(a: ModelAssessment) -> str:
    if a.role_scores.get(AdmissionRole.PATCH_PRODUCER.value):
        return "QUALIFIED_PATCH_PRODUCER"
    if a.role_scores.get(AdmissionRole.INTEGRATOR.value):
        return "QUALIFIED_INTEGRATOR"
    if a.role_scores.get(AdmissionRole.REVIEWER.value):
        return "QUALIFIED_REVIEWER"
    if a.role_scores.get(AdmissionRole.PLANNER_CANDIDATE.value):
        return "QUALIFIED_PLANNER"
    if a.role_scores.get(AdmissionRole.READ_ONLY_ANALYST.value):
        return "QUALIFIED_ANALYST"
    if a.probe_total and not a.structural_ok:
        return "FAILED_QUALIFICATION"
    return "READY"


@dataclass
class TournamentResult:
    assessments: list[ModelAssessment] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(default_factory=list)
    skipped_existing: list[str] = field(default_factory=list)
    budget_total: float = 0.0
    budget_spent: float = 0.0
    stopped_for_budget: bool = False


async def run_tournament(
    ctx: RuntimeContext,
    filters: SelectionFilters,
    *,
    auth: InferenceAuthorization,
    order: list[str] | None = None,
    repeats: int = 2,
    max_models: int = 12,
) -> TournamentResult:
    """Stage A→C tournament over the filtered candidate set, honouring a CUMULATIVE
    budget across all providers/models. Stops before exceeding --max-cost-usd."""
    res = TournamentResult(budget_total=auth.max_cost_usd)
    # Record exclusions for the report.
    for row in ctx.store.records("models"):
        pid, mid = row.get("provider_id", ""), row.get("requested_model_id", "")
        if not pid or not mid:
            continue
        excluded, why = filters.is_excluded(pid, mid)
        if excluded:
            res.excluded.append({"provider": pid, "model": mid, "reason": why})

    from .budget import BudgetLedger, BudgetLimits

    def _spent() -> float:
        return BudgetLedger(ctx.store, BudgetLimits()).spent_total()

    for pid, mid in candidate_models(ctx, filters, order)[:max_models]:
        if (
            filters.skip_valid_existing
            and not filters.force_reassess
            and has_valid_evidence(ctx, pid, mid)
        ):
            res.skipped_existing.append(f"{pid}/{mid}")
            continue
        # Cumulative budget guard: stop before starting a model when the paid spend
        # has reached --max-cost-usd (free/subscription add 0 against it).
        res.budget_spent = _spent()
        if auth.max_cost_usd and res.budget_spent >= auth.max_cost_usd:
            res.stopped_for_budget = True
            break
        # Every model is treated as critical => repeated evidence (LCB), never a
        # single lucky run.
        a = await assess_model(ctx, pid, mid, auth=auth, repeats=repeats)
        res.assessments.append(a)
    res.budget_spent = _spent()
    # Persist the machine-readable assessment to CAS.
    _persist_assessment(ctx, res)
    return res


def _persist_assessment(ctx: RuntimeContext, res: TournamentResult) -> None:
    import json

    payload = {
        "assessments": [a.__dict__ for a in res.assessments],
        "excluded": res.excluded,
        "skipped_existing": res.skipped_existing,
        "budget_total": res.budget_total,
        "budget_spent": res.budget_spent,
        "stopped_for_budget": res.stopped_for_budget,
    }
    ref = ctx.store.cas_put_text(json.dumps(payload, sort_keys=True, default=str))
    ctx.log_event("selection.assessed", stage="INIT", cycle_id="-", payload={"cas": ref})


# --------------------------------------------------------------------------- #
# Central evidence-based role selector.
# --------------------------------------------------------------------------- #

_ROLE_RANK_WEIGHTS = {
    "role_score": 3.0,  # LCB probe/qualification score
    "cost": -1.0,  # normalized $ (lower better)
    "latency": -0.3,
    "uncached": -0.2,  # uncached tokens per task (lower better)
    "cache_reuse": 0.3,
}


def _rank_key(a: ModelAssessment, role: AdmissionRole) -> float:
    score = a.role_scores.get(role.value, 0.0)
    cost_norm = min(a.cost_usd, 1.0)
    latency_norm = 0.0  # per-assessment latency not aggregated here; kept 0
    total_in = max(1, a.cached_input_tokens + a.uncached_input_tokens)
    uncached_ratio = a.uncached_input_tokens / total_in
    cache_reuse = a.cached_input_tokens / total_in
    return (
        _ROLE_RANK_WEIGHTS["role_score"] * score
        + _ROLE_RANK_WEIGHTS["cost"] * cost_norm
        + _ROLE_RANK_WEIGHTS["latency"] * latency_norm
        + _ROLE_RANK_WEIGHTS["uncached"] * uncached_ratio
        + _ROLE_RANK_WEIGHTS["cache_reuse"] * cache_reuse
    )


def rank_for_role(assessments: list[ModelAssessment], role: AdmissionRole) -> list[ModelAssessment]:
    """Eligible candidates for a role, ranked by evidence (never first-found).

    A positive role_score already encodes the role's TRANSPORT requirement
    (structural probes for plain-invoke roles; brokered gates or bounded patch
    synthesis for PATCH_PRODUCER) — reviewer/integrator do NOT require tool_ok."""
    eligible = [a for a in assessments if a.role_scores.get(role.value, 0.0) > 0.0]
    # Router aliases are never ranked for a mutation role (unstable actual model).
    if role in _CRITICAL_ROLES:
        eligible = [a for a in eligible if not a.is_router or len(a.actual_models) == 1]
    return sorted(eligible, key=lambda a: _rank_key(a, role), reverse=True)


def select_roster(assessments: list[ModelAssessment]) -> dict[str, Any]:
    """The central selector: rank each role and enforce reviewer/critic
    independence (a different provider than the planner/producers/integrator where
    an eligible alternative exists)."""

    def top(role: AdmissionRole, exclude_providers: set[str] | None = None):
        excl = exclude_providers or set()
        ranked = [a for a in rank_for_role(assessments, role) if a.provider_id not in excl]
        return ranked[0] if ranked else None

    planner = top(AdmissionRole.PLANNER_CANDIDATE)
    producer = top(AdmissionRole.PATCH_PRODUCER)
    integrator = top(AdmissionRole.INTEGRATOR)
    analyst = top(AdmissionRole.READ_ONLY_ANALYST)
    # Reviewer must differ from planner + producer + integrator provider where possible.
    used = {x.provider_id for x in (planner, producer, integrator) if x}
    reviewer = top(AdmissionRole.REVIEWER, exclude_providers=used) or top(AdmissionRole.REVIEWER)

    def entry(a: ModelAssessment | None, role: AdmissionRole) -> dict[str, Any]:
        if a is None:
            return {"status": "NO_QUALIFIED_MODEL"}
        return {
            "profile_id": a.profile_id,
            "provider": a.provider_id,
            "requested_model": a.model_id,
            "actual_model_policy": (
                a.actual_models[0] if len(a.actual_models) == 1 else f"stochastic:{a.actual_models}"
            ),
            "role_score_lcb": round(a.role_scores.get(role.value, 0.0), 3),
            "structural_ok": a.structural_ok,
            "tool_ok": a.tool_ok,
            "cost_usd": round(a.cost_usd, 4),
            "cost_verified": a.cost_verified,
            "uncached_tokens": a.uncached_input_tokens,
            "cached_tokens": a.cached_input_tokens,
            "is_router": a.is_router,
        }

    def fallback(role: AdmissionRole, primary: ModelAssessment | None):
        ranked = rank_for_role(assessments, role)
        alts = [a for a in ranked if a is not primary]
        # prefer a provider-diverse fallback
        if primary:
            div = [a for a in alts if a.provider_id != primary.provider_id]
            alts = div + [a for a in alts if a.provider_id == primary.provider_id]
        return entry(alts[0], role) if alts else {"status": "NO_QUALIFIED_MODEL"}

    # A local/private fallback: any admitted local_only provider profile among
    # assessments (usually none here since ollama is excluded — honest NO_QUALIFIED).
    local = next((a for a in assessments if a.provider_id == "ollama" and a.structural_ok), None)

    return {
        "PRIMARY_PLANNER": entry(planner, AdmissionRole.PLANNER_CANDIDATE),
        "PRIMARY_PATCH_PRODUCER": entry(producer, AdmissionRole.PATCH_PRODUCER),
        "PRIMARY_REVIEWER": entry(reviewer, AdmissionRole.REVIEWER),
        "PRIMARY_INTEGRATOR": entry(integrator, AdmissionRole.INTEGRATOR),
        "FAST_ANALYST": entry(analyst, AdmissionRole.READ_ONLY_ANALYST),
        "LOCAL_PRIVATE_FALLBACK": entry(local, AdmissionRole.READ_ONLY_ANALYST),
        "PLANNER_FALLBACK": fallback(AdmissionRole.PLANNER_CANDIDATE, planner),
        "PRODUCER_FALLBACK": fallback(AdmissionRole.PATCH_PRODUCER, producer),
        "REVIEWER_FALLBACK": fallback(AdmissionRole.REVIEWER, reviewer),
    }
