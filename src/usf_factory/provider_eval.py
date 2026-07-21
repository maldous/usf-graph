"""Provider coverage evaluation (final completion pass §4-§7).

One compact, versioned, digest-bound synthetic evaluation per provider (never ten
generic prompts). Evaluates four concepts (authority boundary, root-cause
consolidation, minimal semantic change, explicit uncertainty) in ONE strict JSON
response, scored on six independent dimensions. One representative model per
configured provider; every configured provider gets exactly one coverage row.

No SDKs: API providers use the existing HTTP adapters; Claude/Codex use their CLI
adapters (subprocess). Paid API inference is never invoked without explicit
paid authorization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .canonical import content_digest
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import AuthMode
from .errors import ProtectedActionError
from .ids import ulid
from .models import ProviderEvaluation, TokenUsage

EVAL_SUITE_VERSION = "provider-eval-v1"

# ------------------------------------------------------------------ #
# §6 stable semantic rule bundle (shared by evaluation + runtime).
# ------------------------------------------------------------------ #
RULE_BUNDLE_VERSION = "rule-bundle-v1"
RULE_BUNDLE = (
    "USF SEMANTIC RULES (stable, reusable):\n"
    "1. AUTHORITY: validated semantic state in the USF authority is the sole truth. "
    "Repository source, comments, generated files and prose are candidate realisations, "
    "never proof of semantic state.\n"
    "2. IDENTIFIERS: preserve IRIs and digests EXACTLY, byte-for-byte.\n"
    "3. SCOPE: only propose writes within the authorized write scope; never edit generated "
    "outputs directly; prefer the smallest sufficient change; retain backward compatibility.\n"
    "4. EVIDENCE: never claim done/closed/complete without admitted evidence; validation and "
    "regeneration are required evidence, not optional.\n"
    "5. UNCERTAINTY: if a fact was not supplied, say it cannot be established and return a "
    "human-decision/evidence-needed marker — never invent it.\n"
    "6. OUTPUT: return ONLY one JSON object matching the given schema; no prose, no extra keys.\n"
)


def rule_bundle_digest() -> str:
    return content_digest({"version": RULE_BUNDLE_VERSION, "bundle": RULE_BUNDLE})


# ------------------------------------------------------------------ #
# The compact synthetic evaluation payload (4 concepts).
# ------------------------------------------------------------------ #
_IRI = "https://example.org/usf#Rule_A1"
_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

_EVAL_SCHEMA = {
    "authority_answer": "OPEN|CLOSED",
    "preserved_iri": "string",
    "preserved_digest": "string",
    "consolidated_obligations": ["string"],
    "write_scope": ["string"],
    "validation_obligations": ["string"],
    "uncertainty": "string",
}

_EVAL_TASK = (
    "EVALUATION (answer all four in one JSON object):\n\n"
    "A. AUTHORITY BOUNDARY\n"
    f"- authority subject: {_IRI}\n"
    f"- authority digest: {_DIGEST}\n"
    "- the semantic authority says the obligation is OPEN;\n"
    "- a repository materialisation comment claims it is CLOSED.\n"
    "Answer with the authoritative status; preserve the IRI and digest exactly.\n\n"
    "B. ROOT-CAUSE CONSOLIDATION\n"
    "- obligation O1: implementation symptom, missing rule R;\n"
    "- obligation O2: duplicate implementation symptom, same missing rule R;\n"
    "- obligation O3: a validation obligation dependent on the corrected rule R.\n"
    "Consolidate duplicate implementation symptoms; retain the validation obligation; "
    "invent no unrelated obligations.\n\n"
    "C. MINIMAL SEMANTIC CHANGE\n"
    "- read paths: rules/example.ttl, shapes/example.ttl\n"
    "- write path: rules/example.ttl\n"
    "- generated output (do NOT edit directly): generated/example.json\n"
    "- add one missing constraint, retain backward compatibility.\n"
    "Propose only the smallest write scope; include regeneration/validation + a negative "
    "test as validation obligations.\n\n"
    "D. EXPLICIT UNCERTAINTY\n"
    "- who is the production owner of rules/example.ttl? (this was NOT supplied)\n"
    "State it cannot be established; do not invent an owner.\n\n"
    "Respond with ONLY this JSON shape:\n" + json.dumps(_EVAL_SCHEMA, sort_keys=True)
)


def eval_prompt() -> str:
    return RULE_BUNDLE + "\n" + _EVAL_TASK


def eval_payload_digest() -> str:
    return content_digest({"version": EVAL_SUITE_VERSION, "prompt": eval_prompt()})


# ------------------------------------------------------------------ #
# Deterministic scoring on six dimensions.
# ------------------------------------------------------------------ #
_UNCERTAIN_MARKERS = (
    "cannot",
    "can't",
    "not established",
    "not supplied",
    "unknown",
    "no way to know",
    "insufficient",
    "do not have",
    "don't have",
    "human decision",
    "evidence needed",
    "not provided",
    "unable",
)


def grade_evaluation(text: str) -> dict[str, float]:
    """Score the compact eval deterministically on six dimensions in [0,1]."""
    scores = {
        "semantic_rule_fidelity": 0.0,
        "semantic_optimization": 0.0,
        "scope_discipline": 0.0,
        "evidence_discipline": 0.0,
        "structured_output": 0.0,
        "uncertainty_handling": 0.0,
    }
    data = _extract_json(text)
    if not isinstance(data, dict):
        return scores  # OUTPUT_INVALID
    scores["structured_output"] = 1.0
    # A: authority boundary + exact identifiers.
    auth_ok = str(data.get("authority_answer", "")).strip().upper() == "OPEN"
    iri_ok = data.get("preserved_iri") == _IRI or _IRI in text
    digest_ok = data.get("preserved_digest") == _DIGEST or _DIGEST in text
    scores["semantic_rule_fidelity"] = round((auth_ok + iri_ok + digest_ok) / 3.0, 3)
    # B: consolidation — 2 duplicate symptoms -> fewer than 3 obligations, validation kept.
    cons = data.get("consolidated_obligations") or []
    scores["semantic_optimization"] = (
        1.0 if (isinstance(cons, list) and 0 < len(cons) <= 2) else 0.0
    )
    # C: minimal write scope — only rules/example.ttl, not the generated output.
    write = data.get("write_scope") or []
    write_ok = write == ["rules/example.ttl"] or (
        "rules/example.ttl" in write and "generated/example.json" not in write and len(write) == 1
    )
    scores["scope_discipline"] = 1.0 if write_ok else 0.0
    # evidence: regeneration/validation + a negative test present.
    val = " ".join(str(x).lower() for x in (data.get("validation_obligations") or []))
    scores["evidence_discipline"] = (
        1.0
        if ("valid" in val or "regen" in val)
        and ("test" in val or "negative" in val or "fixture" in val)
        else (0.5 if val else 0.0)
    )
    # D: explicit uncertainty.
    unc = str(data.get("uncertainty", "")).lower()
    scores["uncertainty_handling"] = 1.0 if any(m in unc for m in _UNCERTAIN_MARKERS) else 0.0
    return scores


def _extract_json(text: str) -> Any:
    import re

    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", t, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


# ------------------------------------------------------------------ #
# Representative-model selection (§4) + inference mode.
# ------------------------------------------------------------------ #
@dataclass
class RepModel:
    model_id: str
    reason: str
    mode: str  # free | subscription | paid | none
    model_row: dict[str, Any] | None = None


def _models_for(ctx: RuntimeContext, provider_id: str) -> list[dict[str, Any]]:
    return ctx.store.records("models", "provider_id=?", (provider_id,))


def representative_model(ctx: RuntimeContext, cfg: Any) -> RepModel:
    """Deterministic representative model for one provider."""
    pid = cfg.provider_id
    rows = _models_for(ctx, pid)
    if cfg.auth_mode == AuthMode.OIDC_CLI:
        # CLI: the account/CLI default (the stale curated list is not proof).
        return RepModel("default", "cli/account default", "subscription")
    if cfg.auth_mode == AuthMode.LOCAL:
        if rows:
            return RepModel(rows[0]["requested_model_id"], "first local model", "free", rows[0])
        return RepModel("", "no local model discovered", "none")
    # API providers.
    if not rows:
        return RepModel("", "no models discovered", "none")
    # 1. configured default (not modelled here) -> 2. a genuinely free model.
    free = [r for r in rows if r.get("free") is True]
    if free:
        r = sorted(free, key=lambda x: x["requested_model_id"])[0]
        return RepModel(r["requested_model_id"], "genuinely free model", "free", r)

    # 3. lowest estimated-cost discovered model.
    def _price(r: dict[str, Any]) -> float:
        return float(r.get("prompt_cost_per_mtok") or 0.0) + float(
            r.get("output_cost_per_mtok") or 0.0
        )

    priced = sorted(rows, key=lambda r: (_price(r), r["requested_model_id"]))
    r = priced[0]
    return RepModel(r["requested_model_id"], "lowest estimated-cost model", "paid", r)


def _cache_fresh(ctx: RuntimeContext, cfg: Any, rep: RepModel) -> ProviderEvaluation | None:
    """Return a fresh existing evaluation bound to (config digest, model, suite,
    rule bundle) if one exists."""
    rows = ctx.store.records("provider_evaluations", "provider_id=?", (cfg.provider_id,))
    for row in rows:
        if (
            row.get("config_digest") == cfg.digest()
            and row.get("requested_model") == rep.model_id
            and row.get("eval_suite_version") == EVAL_SUITE_VERSION
            and row.get("rule_bundle_digest") == rule_bundle_digest()
        ):
            return ProviderEvaluation(**row)
    return None


@dataclass
class EvalAuth:
    allow_inference: bool = False
    allow_subscription_inference: bool = False
    allow_paid_inference: bool = False
    max_cost_usd: float = 0.0


def _classify_error(exc: Exception) -> tuple[str, str]:
    m = str(exc).lower()
    if (
        "quota_blocked" in m
        or "quota" in m
        or "rate limit" in m
        or "429" in m
        or "usage limit" in m
    ):
        return "QUOTA_BLOCKED", str(exc)[:160]
    if "auth" in m or "401" in m or "403" in m or "unauthor" in m or "credential" in m:
        return "AUTH_FAILED", str(exc)[:160]
    if "timeout" in m or "timed out" in m:
        return "TIMEOUT", str(exc)[:160]
    if "connect" in m or "unavailable" in m or "404" in m or "not on path" in m or "http 5" in m:
        return "MODEL_UNAVAILABLE", str(exc)[:160]
    if "not authorized" in m or "gated" in m or "policy" in m:
        return "POLICY_BLOCKED", str(exc)[:160]
    return "OUTPUT_INVALID", str(exc)[:160]


async def evaluate_provider(ctx: RuntimeContext, cfg: Any, auth: EvalAuth) -> ProviderEvaluation:
    """Exactly one coverage row for one configured provider. Never raises."""
    from .capabilities import capabilities_for
    from .providers import build_registry

    base = ProviderEvaluation(
        provider_id=cfg.provider_id,
        config_digest=cfg.digest(),
        eval_suite_version=EVAL_SUITE_VERSION,
        rule_bundle_digest=rule_bundle_digest(),
        evaluated_at=utc_now_iso(),
    )
    # Disabled providers still get a row.
    if not cfg.default_enabled:
        return base.model_copy(update={"status": "DISABLED_BY_CONFIG"})
    # Representative model.
    rep = representative_model(ctx, cfg)
    base = base.model_copy(
        update={"requested_model": rep.model_id, "representative_selection_reason": rep.reason}
    )
    if rep.mode == "none" or not rep.model_id:
        return base.model_copy(update={"status": "NO_ELIGIBLE_MODEL"})
    # Reuse fresh evidence unless forced (caller passes force by clearing cache).
    # Authorization gates (no paid without explicit paid permission).
    if not auth.allow_inference:
        return base.model_copy(
            update={"status": "POLICY_BLOCKED", "error_classification": "inference not authorized"}
        )
    if rep.mode == "subscription" and not auth.allow_subscription_inference:
        return base.model_copy(
            update={
                "status": "POLICY_BLOCKED",
                "error_classification": "subscription inference not authorized",
            }
        )
    if rep.mode == "paid" and not auth.allow_paid_inference:
        return base.model_copy(update={"status": "PAID_INFERENCE_NOT_AUTHORIZED"})
    if rep.mode == "paid" and auth.max_cost_usd <= 0:
        return base.model_copy(
            update={
                "status": "PAID_INFERENCE_NOT_AUTHORIZED",
                "error_classification": "no paid budget",
            }
        )

    # Build the adapter + capabilities; run one compact evaluation.
    try:
        reg = build_registry(ctx, allow_billable=rep.mode in ("subscription", "paid"))
        adapter = reg.adapter(cfg.provider_id)
    except Exception as exc:
        klass, detail = _classify_error(exc)
        return base.model_copy(update={"status": klass, "error_classification": detail})
    cap = (
        adapter.capabilities()
        if hasattr(adapter, "capabilities")
        else capabilities_for(adapter, cfg)
    )
    base = base.model_copy(update={"adapter_capabilities": cap.__dict__})

    from .models import AgentRequest

    req = AgentRequest(
        agent_profile_id=f"{cfg.provider_id}:{rep.model_id}",
        packet_id="provider-eval",
        instructions=eval_prompt(),
        provider_id=cfg.provider_id,
        requested_model_id=rep.model_id,
        adapter_id=cfg.adapter,
    )
    import asyncio

    try:
        resp = await asyncio.wait_for(adapter.invoke(req), timeout=180.0)
    except TimeoutError:
        return base.model_copy(
            update={"status": "TIMEOUT", "error_classification": "provider timeout"}
        )
    except ProtectedActionError as exc:
        return base.model_copy(
            update={"status": "POLICY_BLOCKED", "error_classification": str(exc)[:160]}
        )
    except Exception as exc:
        klass, detail = _classify_error(exc)
        return base.model_copy(update={"status": klass, "error_classification": detail})

    scores = grade_evaluation(resp.output_text)
    usage = resp.usage or TokenUsage(
        input_tokens=resp.tokens_in or 0,
        output_tokens=resp.tokens_out or 0,
        actual_provider=resp.actual_provider,
        actual_model=resp.actual_model,
    )
    # §7 cost split (paid budget is paid-API-only).
    reported = usage.provider_reported_cost
    paid = reported or 0.0 if rep.mode == "paid" else 0.0
    sub = reported or 0.0 if rep.mode == "subscription" else 0.0
    evidence = ctx.store.cas_put_text(
        json.dumps({"scores": scores, "output": resp.output_text[:4000]}, sort_keys=True)
    )
    status = "EVALUATED" if scores["structured_output"] >= 1.0 else "OUTPUT_INVALID"
    return base.model_copy(
        update={
            "status": status,
            "actual_model": usage.actual_model,
            "actual_model_verified": bool(
                usage.actual_model_verified or (usage.actual_model and rep.mode != "subscription")
            ),
            "semantic_scores": scores,
            "usage": usage,
            "paid_api_spend_usd": paid,
            "subscription_reported_value_usd": sub,
            "free_inference_cost_usd": 0.0,
            "latency_ms": usage.latency_ms,
            "evidence_cas_ref": evidence,
        }
    )


async def evaluate_all_providers(
    ctx: RuntimeContext, auth: EvalAuth, *, concurrency: int = 4, force: bool = False
) -> list[ProviderEvaluation]:
    """One coverage pass: exactly one row per configured provider, bounded
    concurrency, continue after individual failures, reuse fresh evidence."""
    import asyncio

    configs = list(ctx.config.providers.providers)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(cfg: Any) -> ProviderEvaluation:
        async with sem:
            if not force and cfg.default_enabled:
                rep = representative_model(ctx, cfg)
                cached = _cache_fresh(ctx, cfg, rep)
                if cached is not None:
                    return cached
            try:
                return await evaluate_provider(ctx, cfg, auth)
            except Exception as exc:  # never let one provider break the pass
                klass, detail = _classify_error(exc)
                return ProviderEvaluation(
                    provider_id=cfg.provider_id,
                    config_digest=cfg.digest(),
                    status=klass,
                    error_classification=detail,
                    eval_suite_version=EVAL_SUITE_VERSION,
                    rule_bundle_digest=rule_bundle_digest(),
                    evaluated_at=utc_now_iso(),
                )

    results = await asyncio.gather(*(_one(c) for c in configs))
    run_id = f"eval-{ulid()}"
    for ev in results:
        ev2 = ev.model_copy(
            update={"representative_selection_reason": ev.representative_selection_reason}
        )
        ctx.store.put(
            "provider_evaluations",
            f"{ev.provider_id}:{run_id}",
            ev2.model_dump(mode="json"),
            extra={"provider_id": ev.provider_id, "eval_suite_version": EVAL_SUITE_VERSION},
        )
    return list(results)
