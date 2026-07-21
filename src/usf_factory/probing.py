"""Genuine mechanical probing (Phase 3).

Runs the canonical probe suite against a LIVE model through its adapter, grades
each probe deterministically, and persists an immutable ``ProbeRun``. Inference
is gated by explicit controls and a durable budget reservation — a non-empty
response is never a passing probe (the graders decide).

Inference modes and their required authorizations:

    free          local (ollama) or a genuinely zero-price model   --allow-inference, cost 0
    subscription  Codex/Claude OIDC/CLI                             --allow-subscription-inference
    paid          paid API inference                                --allow-paid-inference + budget
"""

from __future__ import annotations

from dataclasses import dataclass

from .budget import BudgetLedger, BudgetLimits
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import AuthMode
from .errors import ProtectedActionError
from .ids import ulid
from .models import AgentProfile, ProbeRun
from .probes import default_probe_specs


@dataclass
class InferenceAuthorization:
    allow_inference: bool = False
    allow_subscription_inference: bool = False
    allow_paid_inference: bool = False
    max_cost_usd: float = 0.0


def classify_inference_mode(profile: AgentProfile, model_row: dict | None) -> str:
    """free | subscription | paid, from provider trust tier + catalogue price."""
    if profile.auth_mode == AuthMode.LOCAL:
        return "free"
    if profile.auth_mode in (AuthMode.OIDC_CLI,):
        return "subscription"
    # External API: free iff the catalogue records a zero-price/free model.
    if model_row is not None and model_row.get("free") is True:
        return "free"
    return "paid"


def _authorize(mode: str, auth: InferenceAuthorization, est_cost: float) -> tuple[bool, str]:
    if not auth.allow_inference:
        return False, "inference not authorized (need --allow-inference)"
    if mode == "free":
        if est_cost > auth.max_cost_usd:
            return False, f"estimated cost {est_cost} exceeds --max-cost-usd {auth.max_cost_usd}"
        return True, "free/local inference authorized"
    if mode == "subscription":
        if not auth.allow_subscription_inference:
            return False, "subscription inference needs --allow-subscription-inference"
        return True, "subscription inference authorized"
    # paid
    if not auth.allow_paid_inference:
        return False, "paid inference needs --allow-paid-inference"
    if auth.max_cost_usd <= 0:
        return False, "paid inference needs a positive --max-cost-usd"
    if est_cost > auth.max_cost_usd:
        return False, f"estimated cost {est_cost} exceeds --max-cost-usd {auth.max_cost_usd}"
    return True, "paid inference authorized"


def _model_row(ctx: RuntimeContext, provider_id: str, model_id: str) -> dict | None:
    for row in ctx.store.records("models", "provider_id=?", (provider_id,)):
        if row.get("requested_model_id") == model_id:
            return row
    return None


def _est_cost(model_row: dict | None) -> float:
    if not model_row:
        return 0.0
    pin = float(model_row.get("prompt_cost_per_mtok") or 0.0)
    pout = float(model_row.get("output_cost_per_mtok") or 0.0)
    # 10 probes, ~500 prompt + 200 output tokens each.
    return (pin * 5000 + pout * 2000) / 1_000_000.0


async def run_probe_suite(
    ctx: RuntimeContext,
    profile: AgentProfile,
    *,
    auth: InferenceAuthorization,
) -> ProbeRun:
    """Run every canonical probe against the live model; persist an immutable
    ProbeRun. Reserves/settles the budget. Raises ProtectedActionError when the
    inference mode is not authorized (nothing is invoked, nothing persisted)."""
    from .providers import build_registry

    model_row = _model_row(ctx, profile.provider_id, profile.requested_model_id)
    est_cost = _est_cost(model_row)
    mode = classify_inference_mode(profile, model_row)
    ok, why = _authorize(mode, auth, est_cost)
    if not ok:
        raise ProtectedActionError(f"probe not authorized ({mode}): {why}")

    ledger = BudgetLedger(ctx.store, BudgetLimits(global_usd=max(auth.max_cost_usd, 0.0)))
    reserved, rwhy = ledger.reserve(
        cycle_id="probe", provider_id=profile.provider_id, estimate_usd=est_cost
    )
    if not reserved:
        raise ProtectedActionError(f"probe budget blocked: {rwhy}")

    allow_billable = mode in ("subscription", "paid")
    reg = build_registry(ctx, allow_billable=allow_billable)
    adapter = reg.adapter(profile.provider_id)

    started = utc_now_iso()
    specs = default_probe_specs()
    results = []
    errors: list[str] = []
    actual_models: set[str] = set()
    tokens_in = tokens_out = 0
    try:
        for spec in specs:
            try:
                res = await adapter.probe_model(profile.requested_model_id, spec)
                results.append(res)
                if res.actual_model_id:
                    actual_models.add(res.actual_model_id)
            except Exception as exc:  # one probe failing must not lose the run
                errors.append(f"{spec.kind.value}: {type(exc).__name__}: {exc}")
    finally:
        # Free/local settles to 0; paid would settle provider-reported cost (not
        # available from probe_model here, so the reservation is released).
        actual = 0.0
        if est_cost:
            ledger.commit(
                cycle_id="probe",
                provider_id=profile.provider_id,
                estimate_usd=est_cost,
                actual_usd=actual,
            )

    passed = sum(1 for r in results if r.passed)
    run = ProbeRun(
        run_id=f"probe-{ulid()}",
        agent_profile_id=profile.profile_id,
        provider_id=profile.provider_id,
        requested_model_id=profile.requested_model_id,
        adapter_id=profile.adapter,
        config_digest=profile.digest(),
        actual_models=sorted(actual_models),
        results=results,
        passed=passed,
        total=len(specs),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=0.0 if mode == "free" else est_cost,
        inference_mode=mode,
        errors=errors,
        started_at=started,
        ended_at=utc_now_iso(),
    )
    ctx.store.put(
        "probe_runs",
        run.run_id,
        run.model_dump(mode="json"),  # id-keyed record: preserve timestamps
        extra={"agent_profile_id": profile.profile_id},
    )
    return run


def latest_probe_run(ctx: RuntimeContext, profile_id: str) -> dict | None:
    rows = ctx.store.records("probe_runs", "agent_profile_id=?", (profile_id,))
    return rows[-1] if rows else None


def probe_gates_pass(run: ProbeRun) -> bool:
    """Minimum bar to proceed to qualification: the deterministic/structural
    probes (IRI/digest preservation, strict JSON, stop condition) must pass —
    these are non-negotiable for semantic work."""
    required = {"iri_preservation", "digest_preservation", "strict_json", "stop_condition"}
    got = {r.kind.value for r in run.results if r.passed}
    return required.issubset(got)
