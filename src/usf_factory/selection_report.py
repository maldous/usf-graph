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
