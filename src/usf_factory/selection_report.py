"""Render the provider/model selection report (milestone item 10)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def render_report(res: Any, roster: dict[str, Any], filters: Any) -> str:
    lines: list[str] = []
    a_ = lines.append
    a_("# Provider / model selection report")
    a_("")
    a_(
        "Staged non-Llama tournament (Stage A metadata → B genuine mechanical "
        "probes, repeated for LCB → role eligibility → central ranked selector). "
        "All protected actions disabled; `/usf` unchanged; no private source sent "
        "to external providers (probes use generic, non-sensitive prompts)."
    )
    a_("")
    a_("## Selection controls")
    a_("")
    a_(f"- excluded providers: `{filters.exclude_providers}`")
    a_(f"- excluded families: `{filters.exclude_families}`")
    a_(f"- excluded models: `{filters.exclude_models}`")
    a_(f"- include (forced): `{filters.include_models}`")
    a_(
        f"- skip_valid_existing: `{filters.skip_valid_existing}`  force_reassess: `{filters.force_reassess}`"
    )
    a_(
        f"- budget: spent ${res.budget_spent} / cap ${res.budget_total}"
        + ("  (STOPPED for budget)" if res.stopped_for_budget else "")
    )
    a_("")
    a_("## Excluded models (with reason)")
    a_("")
    if res.excluded:
        a_("| provider | model | reason |")
        a_("| --- | --- | --- |")
        for e in res.excluded[:200]:
            a_(f"| {e['provider']} | `{e['model']}` | {e['reason']} |")
    else:
        a_("_none_")
    a_("")
    a_("## Skipped (valid existing evidence)")
    a_("")
    a_(", ".join(f"`{s}`" for s in res.skipped_existing) or "_none_")
    a_("")
    a_("## Assessment matrix (Stage B, repeated → LCB)")
    a_("")
    a_(
        "| provider | model | probes | class | structural | tool | actual model(s) | in/out tok | cached | cost | verified |"
    )
    a_("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for a in res.assessments:
        a_(
            f"| {a.provider_id} | `{a.model_id}` | {a.probe_passed}/{a.probe_total} | "
            f"{a.classification} | {'✅' if a.structural_ok else '❌'} | "
            f"{'✅' if a.tool_ok else '—'} | {','.join(a.actual_models) or '?'} | "
            f"{a.tokens_in}/{a.tokens_out} | {a.cached_input_tokens} | "
            f"${round(a.cost_usd, 4)} | {'yes' if a.cost_verified else 'est'} |"
        )
    a_("")
    a_("## Cache measurement")
    a_("")
    total_cached = sum(a.cached_input_tokens for a in res.assessments)
    total_unc = sum(a.uncached_input_tokens for a in res.assessments)
    a_(f"- aggregate cached input tokens: **{total_cached}**")
    a_(f"- aggregate uncached input tokens: **{total_unc}** (principal efficiency metric)")
    a_(
        "- providers reporting cache reads (e.g. Claude CLI) demonstrate real "
        "provider-native caching across the repeated probe rounds."
    )
    a_("")
    a_("## Proposed roster")
    a_("")
    for role, choice in roster.items():
        a_(f"### {role}")
        if choice.get("status") == "NO_QUALIFIED_MODEL":
            a_(
                "`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled)."
            )
            a_("")
            continue
        a_(f"- profile: `{choice.get('profile_id')}`")
        a_(f"- provider / model: `{choice.get('provider')}` / `{choice.get('requested_model')}`")
        a_(f"- actual-model policy: `{choice.get('actual_model_policy')}`")
        a_(
            f"- role score (LCB): {choice.get('role_score_lcb')}  structural={choice.get('structural_ok')} tool={choice.get('tool_ok')}"
        )
        a_(
            f"- cost: ${choice.get('cost_usd')} ({'verified' if choice.get('cost_verified') else 'estimate'})  uncached_tokens={choice.get('uncached_tokens')} cached={choice.get('cached_tokens')}"
        )
        a_(f"- router: {choice.get('is_router')}")
        a_("")
    a_("## Notes / known weaknesses")
    a_("")
    a_(
        "- CLI adapters (Codex/Claude) drive text/structured roles well but have no "
        "brokered `chat_with_tools`, so they are not eligible as brokered "
        "PATCH_PRODUCER/INTEGRATOR workers (tool_ok=—). Tool roles require an "
        "OpenAI-compatible adapter with native tool calling."
    )
    a_(
        "- Router aliases are treated as stochastic services; a mutation role is "
        "never assigned to a router whose actual model is not stable."
    )
    a_(
        "- Mutation-role admission uses the lower confidence bound over repeated "
        "rounds, never a single best run."
    )
    return "\n".join(lines) + "\n"


def write_report(md: str, path: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(md, encoding="utf-8")
    return str(p)


def build_and_persist_roster(ctx: Any, evals: Any) -> dict[str, Any]:
    """Build the active RoleRoster from current admission evidence and persist it
    (§8). Returns the roster entries for the report."""
    from .roster import build_roster, persist_active

    roster = build_roster(ctx)
    persist_active(ctx, roster)
    return roster.entries


def render_coverage_report(evals: Any, roster: dict[str, Any]) -> str:
    """One concise provider-coverage report (final completion pass §12)."""
    lines: list[str] = []
    a_ = lines.append
    a_("# Provider evaluation report")
    a_("")
    a_(
        "One coverage pass — exactly one representative model per CONFIGURED "
        "provider, one compact semantic evaluation (authority boundary, root-cause "
        "consolidation, minimal change, uncertainty). No paid API inference. "
        "`/usf` unchanged; all protected gates disabled."
    )
    a_("")
    a_(
        "| provider | representative requested model | actual model | status | fidelity | optimization | safe transport | uncached/cached/output tok | latency ms | blocker |"
    )
    a_("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for e in sorted(evals, key=lambda x: x.provider_id):
        caps = e.adapter_capabilities or {}
        transport = (
            "brokered_tool_loop"
            if caps.get("brokered_tool_loop")
            else ("bounded_patch_synthesis" if caps.get("bounded_patch_synthesis") else "-")
        )
        u = e.usage
        unc = getattr(u, "uncached_input_tokens", 0) if u else 0
        cac = getattr(u, "cached_input_tokens", 0) if u else 0
        out = getattr(u, "output_tokens", 0) if u else 0
        toks = f"{unc}/{cac}/{out}" if (e.status == "EVALUATED") else "UNKNOWN"
        fid = (
            f"{e.semantic_scores.get('semantic_rule_fidelity', 0):.2f}"
            if e.semantic_scores
            else "-"
        )
        opt = (
            f"{e.semantic_scores.get('semantic_optimization', 0):.2f}" if e.semantic_scores else "-"
        )
        actual = (
            e.actual_model if e.actual_model else ("unverified" if e.status == "EVALUATED" else "-")
        )
        lat = f"{e.latency_ms:.0f}" if e.latency_ms else "-"
        a_(
            f"| {e.provider_id} | `{e.requested_model or '-'}` | {actual} | {e.status} | "
            f"{fid} | {opt} | {transport} | {toks} | {lat} | {e.error_classification or '-'} |"
        )
    a_("")
    a_("## Active role roster")
    a_("")
    for role, entry in sorted(roster.items()):
        if not entry.get("primary"):
            a_(f"- **{role}**: NO_QUALIFIED_MODEL (unfilled; not force-filled)")
            continue
        indep = (
            f"  reviewer_independence={entry['reviewer_independence']}"
            if "reviewer_independence" in entry
            else ""
        )
        a_(
            f"- **{role}**: `{entry.get('provider')}` / `{entry.get('requested_model')}` "
            f"(transport={entry.get('transport')}; profile={entry.get('primary')[:16]}; "
            f"qual={entry.get('qualification_run_id') or 'none'}; fallbacks={len(entry.get('fallbacks', []))}){indep}"
        )
    a_("")
    a_("## Cost accounting")
    a_("")
    paid = sum(e.paid_api_spend_usd for e in evals)
    sub = sum(e.subscription_reported_value_usd for e in evals)
    a_(f"- **paid API spend: ${paid:.2f}** (must be $0.00; no paid inference authorized)")
    a_(f"- subscription reported value: ${sub:.4f} (informational; not against the paid budget)")
    a_("- free inference cost: $0.00")
    a_("")
    a_("## Notes")
    a_("")
    a_(
        "- Every configured provider has exactly one row (disabled => "
        "DISABLED_BY_CONFIG; paid-only without paid authorization => "
        "PAID_INFERENCE_NOT_AUTHORIZED — never omitted for un-runnable inference)."
    )
    a_(
        "- Reviewer/integrator require only plain invocation; PATCH_PRODUCER "
        "accepts brokered tool loop OR bounded patch synthesis (Claude/Codex CLIs)."
    )
    a_("- Auth/quota/model-id failures are classified as such — not model-quality failures.")
    return "\n".join(lines) + "\n"
