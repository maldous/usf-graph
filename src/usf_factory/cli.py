"""`usf-factory` command-line interface (Typer + Rich).

Safe by default: observe / plan-only enabled; billable inference, source egress,
and publication disabled unless explicitly configured. No command mutates /usf.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, secrets
from .context import RuntimeContext, build_context
from .enums import RunMode
from .paths import ENV_FILE

console = Console()
err = Console(stderr=True)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="USF Adaptive Semantic Factory — deterministic, model-agnostic orchestration.",
)
env_app = typer.Typer(no_args_is_help=True, help="Credential import/status (names only).")
providers_app = typer.Typer(no_args_is_help=True, help="Provider discovery and status.")
models_app = typer.Typer(no_args_is_help=True, help="Model discovery, probing, qualification.")
usf_app = typer.Typer(no_args_is_help=True, help="Read-only USF authority (MCP) access.")
cycle_app = typer.Typer(no_args_is_help=True, help="Cycle phases: snapshot, plan, show, status.")
maint_app = typer.Typer(no_args_is_help=True, help="Maintenance: backup, garbage collection.")
mat_app = typer.Typer(no_args_is_help=True, help="Materialisation index (subject -> repo surface).")
app.add_typer(env_app, name="env")
app.add_typer(providers_app, name="providers")
app.add_typer(models_app, name="models")
app.add_typer(usf_app, name="usf")
app.add_typer(cycle_app, name="cycle")
app.add_typer(maint_app, name="maintenance")
app.add_typer(mat_app, name="materialisation")


def _ctx() -> RuntimeContext:
    return build_context()


def _status_color(status: str) -> str:
    return {"ok": "green", "warn": "yellow", "fail": "red"}.get(status, "white")


# --------------------------------------------------------------------------- #
# Top-level.
# --------------------------------------------------------------------------- #


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"usf-factory {__version__}")


@app.command()
def doctor(
    skip_mcp: bool = typer.Option(False, "--skip-mcp", help="Skip the USF MCP health check."),
) -> None:
    """Environment, config, isolation, and safety self-check."""
    from .doctor import overall_status, run_doctor

    with _ctx() as ctx:
        checks = run_doctor(ctx, check_mcp=not skip_mcp)
    table = Table(title="usf-factory doctor", show_lines=False)
    table.add_column("check", style="bold")
    table.add_column("status")
    table.add_column("detail")
    for c in checks:
        table.add_row(c.name, f"[{_status_color(c.status)}]{c.status}[/]", c.detail)
    console.print(table)
    overall = overall_status(checks)
    console.print(f"overall: [{_status_color(overall)}]{overall}[/]")
    if overall == "fail":
        raise typer.Exit(code=1)


@app.command()
def status() -> None:
    """Show recent cycles and pause state."""
    with _ctx() as ctx:
        paused = (ctx.paths.state / "PAUSED").exists()
        console.print(f"paused: {'[yellow]yes[/]' if paused else 'no'}")
        cycles = sorted(ctx.store.items("cycles"), key=lambda t: t[0])
        table = Table(title="recent cycles")
        for col in ("cycle", "mode", "state", "selected", "accepted", "no_progress"):
            table.add_column(col)
        for cid, c in cycles[-10:]:
            table.add_row(
                cid,
                str(c.get("mode")),
                str(c.get("state")),
                str(c.get("selected_packets")),
                str(c.get("accepted_packets")),
                str(c.get("no_progress")),
            )
        console.print(table)


@app.command()
def pause() -> None:
    """Pause the factory (sets a flag the engine honors before a new cycle)."""
    with _ctx() as ctx:
        (ctx.paths.state / "PAUSED").write_text("paused\n", encoding="utf-8")
    console.print("[yellow]paused[/]")


@app.command()
def resume() -> None:
    """Clear the pause flag."""
    with _ctx() as ctx:
        flag = ctx.paths.state / "PAUSED"
        if flag.exists():
            flag.unlink()
    console.print("[green]resumed[/]")


@app.command()
def replay(cycle_id: str) -> None:
    """Replay a cycle's event log (deterministic history)."""
    with _ctx() as ctx:
        events = ctx.store.events(cycle_id)
    if not events:
        err.print(f"[red]no events for cycle {cycle_id}[/]")
        raise typer.Exit(code=1)
    table = Table(title=f"replay {cycle_id}")
    table.add_column("kind")
    table.add_column("stage")
    table.add_column("payload")
    for e in events:
        table.add_row(
            e.get("kind", ""), e.get("stage", ""), secrets.redact(str(e.get("payload", {})))[:100]
        )
    console.print(table)


@app.command()
def run(
    mode: str = typer.Option(
        "plan-only", "--mode", help="observe | plan-only | shadow | approve-wave | autonomous-safe"
    ),
    continuous: bool = typer.Option(
        False, "--continuous", help="loop until no-progress / quota / blocker / pause"
    ),
    max_cycles: int = typer.Option(20, "--max-cycles", help="hard cap for --continuous"),
    shadow_packets: int = typer.Option(
        -1, "--shadow-packets", help="cap packets actually dispatched in shadow mode (-1=no cap)"
    ),
    allow_subscription_inference: bool = typer.Option(
        False,
        "--allow-subscription-inference",
        help="authorize subscription (Claude/Codex CLI) + free inference for this run "
        "(the paid-inference gate stays off)",
    ),
    approve_source_provider: list[str] = typer.Option(
        [],
        "--approve-source-provider",
        help="audited: approve a proven-contained provider to receive raw source for "
        "this run only (in-memory; never committed)",
    ),
) -> None:
    """Run one cycle (or a bounded continuous loop) in the given mode.

    ``--continuous`` (Phase 16): refresh -> snapshot -> plan -> execute ->
    integrate analysis -> metrics, stopping on no-progress, a blocker, pause, or
    the cycle cap. It never re-runs an unchanged packet set and keeps merge /
    publication / terminal completion disabled. A candidate-patch flow halts at
    AWAITING_OPERATOR_DELIVERY."""
    try:
        run_mode = RunMode(mode)
    except ValueError:
        err.print(
            f"[red]unknown mode '{mode}'. Use observe | plan-only | shadow | approve-wave | autonomous-safe.[/]"
        )
        raise typer.Exit(code=2) from None
    from .runtime import build_engine

    cap = shadow_packets if shadow_packets >= 0 else None
    with _ctx() as ctx:
        if (ctx.paths.state / "PAUSED").exists():
            err.print("[yellow]factory is paused; run `usf-factory resume` first[/]")
            raise typer.Exit(code=1)
        if approve_source_provider:
            ctx.config.egress.source_egress_enabled = True
            overrides = dict(ctx.config.egress.provider_overrides or {})
            for pid in approve_source_provider:
                overrides[pid] = sorted({*overrides.get(pid, []), "private-source"})
            ctx.config.egress.provider_overrides = overrides
            console.print(
                f"[yellow]audited source-egress approval for: {approve_source_provider}[/]"
            )
        if not continuous:
            eng = build_engine(
                ctx,
                mode=run_mode,
                max_shadow_packets=cap,
                allow_billable=allow_subscription_inference,
            )
            receipt = asyncio.run(eng.run_cycle(run_mode))
            _print_receipt(receipt)
            return
        # Continuous shadow loop (bounded, fail-closed stop conditions).
        seen_sets: set[str] = set()
        for i in range(max(1, max_cycles)):
            if (ctx.paths.state / "PAUSED").exists():
                console.print("[yellow]paused; stopping continuous loop[/]")
                break
            eng = build_engine(ctx, mode=run_mode, allow_billable=allow_subscription_inference)
            receipt = asyncio.run(eng.run_cycle(run_mode))
            console.print(
                f"cycle {i + 1}: state={receipt.state.value} "
                f"selected={receipt.selected_packets} accepted={receipt.accepted_packets}"
            )
            if receipt.set_id and receipt.set_id in seen_sets:
                console.print("[dim]same packet set as a prior cycle; stopping (no progress)[/]")
                break
            if receipt.set_id:
                seen_sets.add(receipt.set_id)
            if receipt.no_progress:
                console.print("[dim]no progress; stopping[/]")
                break
            if receipt.state.value == "BLOCKED":
                console.print(f"[yellow]blocked: {receipt.blockers}; stopping[/]")
                break
            if receipt.selected_packets == 0:
                console.print("[dim]nothing to do; stopping[/]")
                break


@app.command("bootstrap-runtime")
def bootstrap_runtime_cmd(
    allow_inference: bool = typer.Option(False, "--allow-inference", help="free/local inference"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd", help="paid API budget (kept 0)"),
    max_cases: int = typer.Option(0, "--max-cases", help="bounded qualification sample (0=full)"),
    force: bool = typer.Option(False, "--force", help="re-qualify even with fresh evidence"),
) -> None:
    """Clean-state launch bootstrap: refresh, reuse evaluations, qualify only the
    selected role candidates lacking fresh evidence, admit from evidence, build +
    activate the ranked roster, verify freshness, and print the exact unfilled
    roles + blockers. Exits non-zero unless the minimum launch (shadow) roster
    exists. No operator overrides; no lowered thresholds; paid inference off."""
    from .bootstrap import bootstrap_runtime

    with _ctx() as ctx:
        report = asyncio.run(
            bootstrap_runtime(
                ctx,
                allow_subscription_inference=allow_subscription_inference,
                allow_free_inference=allow_inference,
                max_cost_usd=max_cost_usd,
                max_cases=max_cases,
                force=force,
            )
        )
    table = Table(title="active roster")
    table.add_column("role")
    table.add_column("primary")
    table.add_column("provider")
    table.add_column("transport")
    for role, entry in (report.roster.get("entries") or {}).items():
        table.add_row(
            role,
            str(entry.get("primary") or "-")[:20],
            str(entry.get("provider") or "-"),
            str(entry.get("transport") or entry.get("status") or "-"),
        )
    console.print(table)
    console.print(f"qualified: {report.qualified}")
    console.print(f"filled roles: {report.filled_roles}")
    console.print(f"[yellow]unfilled roles: {report.unfilled_roles}[/]")
    if report.blockers:
        console.print(f"[yellow]blockers:[/] {report.blockers}")
    console.print(
        f"roster_fresh={report.roster_fresh} "
        f"minimum_shadow_ok={report.minimum_shadow_ok} "
        f"minimum_candidate_ok={report.minimum_candidate_ok}"
    )
    if not report.minimum_shadow_ok:
        err.print("[red]minimum launch roster (planner + analyst) NOT satisfied[/]")
        raise typer.Exit(code=1)
    console.print("[green]minimum launch roster satisfied[/]")


@app.command("candidate")
def candidate_cmd(
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    approve_source_provider: list[str] = typer.Option(
        [],
        "--approve-source-provider",
        help="explicitly approve a PROVEN-CONTAINED first-party CLI provider to receive "
        "raw source for this audited candidate run (e.g. claude-cli)",
    ),
) -> None:
    """Operator-audited candidate semantic-patch attempt. Enables, FOR THIS RUN
    ONLY (never committed): autonomous-safe wave execution + source egress for the
    explicitly approved, source-contained provider(s). The candidate patch stays
    in the factory integration clone — never applied to /usf, never pushed. Halts
    at AWAITING_OPERATOR_DELIVERY. The paid-inference / push / merge / Stardog /
    risk-acceptance / terminal-completion gates stay OFF."""
    from types import SimpleNamespace

    from .candidate import attempt_candidate_packet

    with _ctx() as ctx:
        # Audited, in-memory-only authorization for this run.
        ctx.config.safety.autonomous_safe_enabled = True
        if approve_source_provider:
            ctx.config.egress.source_egress_enabled = True
            overrides = dict(ctx.config.egress.provider_overrides or {})
            for pid in approve_source_provider:
                overrides[pid] = sorted({*overrides.get(pid, []), "private-source"})
            ctx.config.egress.provider_overrides = overrides
            console.print(
                f"[yellow]audited source-egress approval for: {approve_source_provider}[/]"
            )
        result = attempt_candidate_packet(
            ctx, SimpleNamespace(allow_billable=allow_subscription_inference)
        )
    console.print(result)
    if result.get("status") != "AWAITING_OPERATOR_DELIVERY":
        raise typer.Exit(code=1)


@app.command()
def activate(
    free_only: bool = typer.Option(True, "--free-only/--no-free-only"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    allow_paid_inference: bool = typer.Option(False, "--allow-paid-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd"),
    max_models_per_provider: int = typer.Option(3, "--max-models-per-provider"),
    shadow_packets: int = typer.Option(1, "--shadow-packets"),
    candidate_packet: bool = typer.Option(False, "--candidate-packet"),
    providers: str = typer.Option(
        "", "--providers", help="comma-separated provider ids to bound the run (default: all)"
    ),
    max_qual_cases: int = typer.Option(
        0, "--max-qual-cases", help="bound qualification cases per model (0=full corpus)"
    ),
) -> None:
    """Run the full activation assessment: refresh -> discover -> probe ->
    qualify -> admit -> plan-only -> shadow wave -> (optional) one candidate
    semantic patch -> report. Default budget 0 USD (local/free only); paid
    inference is never a silent fallback."""
    from .activation import ActivationOptions, run_activation

    opts = ActivationOptions(
        free_only=free_only,
        allow_subscription_inference=allow_subscription_inference,
        allow_paid_inference=allow_paid_inference,
        max_cost_usd=max_cost_usd,
        max_models_per_provider=max_models_per_provider,
        shadow_packets=shadow_packets,
        candidate_packet=candidate_packet,
        providers=[p.strip() for p in providers.split(",") if p.strip()],
        max_qual_cases=max_qual_cases,
    )
    with _ctx() as ctx:
        report = run_activation(ctx, opts)
    console.print(
        Panel(
            f"USF ok: {report.usf_ok}  triples: {report.triples}\n"
            f"authority: {report.authority_digest}\nsnapshot: {report.snapshot_id}\n"
            f"repo head: {report.repository_head}",
            title="activation — authority",
        )
    )
    t = Table(title="model outcomes")
    for col in ("provider", "model", "probes", "classification", "roles"):
        t.add_column(col)
    for m in report.model_outcomes:
        t.add_row(
            m.provider_id,
            m.model_id[-28:],
            f"{m.probe_passed}/{m.probe_total}",
            m.classification,
            ",".join(m.roles) or "-",
        )
    console.print(t)
    console.print(f"admitted profiles: {len(report.admitted)}")
    console.print(f"plan-only: {report.plan_only}")
    console.print(f"shadow: {report.shadow}")
    console.print(f"candidate: {report.candidate}")
    console.print(
        f"tokens in/out: {report.tokens_in}/{report.tokens_out}  cost: ${report.cost_usd}"
    )
    if report.blockers:
        console.print(Panel("\n".join(f"- {b}" for b in report.blockers), title="blockers"))
    console.print(Panel(report.next_action, title="next action"))


def _print_receipt(receipt) -> None:
    body = (
        f"cycle:     {receipt.cycle_id}\n"
        f"mode:      {receipt.mode}\n"
        f"state:     {receipt.state.value}\n"
        f"snapshot:  {receipt.snapshot_id}\n"
        f"packets:   {receipt.selected_packets} selected, {receipt.accepted_packets} accepted\n"
        f"no_progress: {receipt.no_progress}\n"
        f"blockers:  {receipt.blockers or 'none'}"
    )
    console.print(Panel(body, title="cycle receipt"))


# --------------------------------------------------------------------------- #
# env
# --------------------------------------------------------------------------- #


@env_app.command("status")
def env_status() -> None:
    """Show which canonical credentials are present, BY NAME ONLY."""
    allow = secrets.load_allowlisted_env(ENV_FILE)
    raw = secrets.load_env_file(ENV_FILE)
    present = sorted(allow)
    missing = sorted(set(secrets.CANONICAL_VARS) - set(present) - secrets.OPTIONAL_CANONICALS)
    excluded_here = sorted(set(raw) & secrets.EXCLUDED_VARS)
    table = Table(title="credential status (names only, no values)")
    table.add_column("category")
    table.add_column("variables")
    table.add_row("present", ", ".join(present) or "-")
    table.add_row("missing (non-optional)", ", ".join(missing) or "-")
    table.add_row(
        "excluded-present (must be 0)",
        f"[red]{', '.join(excluded_here)}[/]" if excluded_here else "-",
    )
    console.print(table)
    if ENV_FILE.exists():
        mode = oct(ENV_FILE.stat().st_mode & 0o777)
        console.print(
            f"{ENV_FILE}: mode {mode}" + ("" if mode == "0o600" else "  [yellow](expected 0600)[/]")
        )
    else:
        console.print(f"[yellow]{ENV_FILE} does not exist[/]")


@env_app.command("import")
def env_import(
    from_process: bool = typer.Option(
        False, "--from-process", help="Import from current environment."
    ),
    stdin0: bool = typer.Option(False, "--stdin0", help="Read NUL-delimited env -0 from stdin."),
    from_env_file: str | None = typer.Option(
        None, "--from-env-file", help="Read from an existing dotenv file."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report names only; write nothing."),
) -> None:
    """Import model-provider credentials into /root/.env (names only in output)."""
    import os
    import sys as _sys

    sources: dict[str, str] = {}
    if from_process:
        sources.update(os.environ)
    if from_env_file:
        from pathlib import Path

        sources.update(secrets.load_env_file(Path(from_env_file)))
    if stdin0:
        data = _sys.stdin.buffer.read()
        sources.update(secrets.parse_env0(data))
    if not (from_process or stdin0 or from_env_file):
        err.print("[red]specify one of --from-process / --stdin0 / --from-env-file[/]")
        raise typer.Exit(code=2)

    norm = secrets.normalize(sources)
    to_write = secrets.select_for_write(norm)
    gm_write, gm_reason = secrets.github_models_write_policy(norm)

    table = Table(title="credential import (names only)")
    table.add_column("field")
    table.add_column("value")
    table.add_row("would write", ", ".join(to_write) or "-")
    table.add_row("conflicts", f"[red]{', '.join(norm.conflicts)}[/]" if norm.conflicts else "-")
    table.add_row("missing", ", ".join(norm.missing) or "-")
    table.add_row("excluded (skipped)", ", ".join(norm.excluded_present) or "-")
    table.add_row("unmapped candidates", ", ".join(norm.unmapped_candidates) or "-")
    table.add_row("github-models", f"{'write' if gm_write else 'skip'}: {gm_reason}")
    console.print(table)

    if dry_run:
        console.print("[cyan]dry-run: nothing written[/]")
        return
    content = secrets.render_env_content(norm, to_write)
    secrets.write_env_file(ENV_FILE, content)
    console.print(f"[green]wrote {len(to_write)} variables to {ENV_FILE} (mode 0600)[/]")


# --------------------------------------------------------------------------- #
# providers
# --------------------------------------------------------------------------- #


@providers_app.command("status")
def providers_status() -> None:
    """Show provider enablement (credential presence by name, never value)."""
    from .providers import build_registry

    with _ctx() as ctx:
        reg = build_registry(ctx)
        table = Table(title="providers")
        for col in ("provider", "enabled", "cred", "probe", "reason"):
            table.add_column(col)
        for pid, st in reg.all_enablement().items():
            table.add_row(
                pid,
                "[green]yes[/]" if st.enabled else "[dim]no[/]",
                "yes" if st.credential_present else "no",
                "yes" if st.requires_probe else "-",
                st.reason,
            )
        console.print(table)
        console.print(f"excluded: {reg.excluded}")


@providers_app.command("refresh")
def providers_refresh(
    provider: str | None = typer.Option(None, "--provider", help="Refresh only this provider."),
) -> None:
    """Refresh provider catalogues (metadata-only; not billable)."""
    from .providers import build_registry

    async def _go(ctx: RuntimeContext):
        reg = build_registry(ctx)
        ids = [provider] if provider else reg.enabled_ids()
        return await reg.discover_all(ids)

    with _ctx() as ctx:
        outcomes = asyncio.run(_go(ctx))
        # Record OBSERVED provider health (scheduler reads this; unrecorded
        # providers stay DEGRADED — health is never fabricated).
        from .clock import utc_now_iso
        from .enums import HealthStatus

        for pid, o in outcomes.items():
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
    table = Table(title="provider refresh")
    for col in ("provider", "ok", "models", "error"):
        table.add_column(col)
    for pid, o in sorted(outcomes.items()):
        table.add_row(
            pid, "[green]yes[/]" if o.ok else "[red]no[/]", str(o.model_count), (o.error or "")[:60]
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #


@models_app.command("discover")
def models_discover() -> None:
    """Discover models across enabled providers (metadata-only)."""
    providers_refresh(provider=None)


@models_app.command("list")
def models_list(provider: str | None = typer.Option(None, "--provider")) -> None:
    """List normalized model records from the store."""
    with _ctx() as ctx:
        where = "provider_id=?" if provider else None
        params = (provider,) if provider else ()
        rows = ctx.store.records("models", where, params)
    table = Table(title=f"models ({len(rows)})")
    for col in ("provider", "model", "family", "ctx", "free"):
        table.add_column(col)
    for r in sorted(
        rows, key=lambda x: (x.get("provider_id", ""), x.get("requested_model_id", ""))
    )[:200]:
        table.add_row(
            r.get("provider_id", ""),
            r.get("requested_model_id", ""),
            r.get("canonical_family", ""),
            str(r.get("context_tokens") or "-"),
            str(r.get("free")),
        )
    console.print(table)


@models_app.command("probe")
def models_probe(
    model: str = typer.Argument(None, help="provider/model to probe LIVE"),
    allow_inference: bool = typer.Option(False, "--allow-inference"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    allow_paid_inference: bool = typer.Option(False, "--allow-paid-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd"),
) -> None:
    """Run the ten mechanical probes against a LIVE model and grade them with the
    canonical graders (a non-empty response is NOT a pass). Persists an immutable
    ProbeRun. A genuinely free/local model runs with `--allow-inference
    --max-cost-usd 0`; subscription and paid inference need their own flags.

    With no argument, prints a graders self-check only (proves graders execute;
    never stored as model evidence)."""
    if not model:
        from .probes import default_probe_specs, grade_probe

        specs = default_probe_specs()
        passed = 0
        for s in specs:
            exp = s.expected
            ref = {
                "iri_preservation": exp.get("iri", ""),
                "digest_preservation": exp.get("digest", ""),
                "stop_condition": "1\n2\n3\n" + exp.get("stop_token", ""),
                "explicit_uncertainty": "I do not know; insufficient information.",
                "text_response": "A checksum detects data corruption.",
            }.get(s.kind.value, "")
            passed += 1 if grade_probe(s, ref).passed else 0
        console.print(f"probe graders self-check: {passed}/{len(specs)} produced a verdict")
        return

    import asyncio as _asyncio

    from .admission import ensure_profile, parse_model_ref
    from .errors import ProtectedActionError
    from .probing import InferenceAuthorization, run_probe_suite

    provider_id, model_id = parse_model_ref(model)
    auth = InferenceAuthorization(
        allow_inference=allow_inference,
        allow_subscription_inference=allow_subscription_inference,
        allow_paid_inference=allow_paid_inference,
        max_cost_usd=max_cost_usd,
    )
    with _ctx() as ctx:
        profile = ensure_profile(ctx, provider_id, model_id)
        console.print(f"profile: [bold]{profile.profile_id}[/] ({provider_id}/{model_id})")
        try:
            run = _asyncio.run(run_probe_suite(ctx, profile, auth=auth))
        except ProtectedActionError as exc:
            console.print(f"[yellow]{exc}[/]")
            raise typer.Exit(code=0) from None
    table = Table(title=f"probe run {run.run_id} ({run.inference_mode})")
    for col in ("probe", "passed", "detail"):
        table.add_column(col)
    for r in run.results:
        table.add_row(r.kind.value, "[green]yes[/]" if r.passed else "[red]no[/]", r.detail[:50])
    console.print(table)
    console.print(
        f"probe run: {run.passed}/{run.total} passed; actual models: {run.actual_models}; "
        f"cost=${run.cost_usd}; errors={len(run.errors)}"
    )


@models_app.command("qualify")
def models_qualify(
    model: str = typer.Argument(None, help="provider/model to qualify LIVE (gated)"),
    allow_inference: bool = typer.Option(False, "--allow-inference"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    allow_paid_inference: bool = typer.Option(False, "--allow-paid-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd"),
) -> None:
    """Run the USF qualification suite.

    Without an argument: a zero-cost SELF-CHECK grades the corpus against
    reference answers (proving the scorer + admission logic execute). Never
    stored as model evidence.

    With provider/model: runs the mechanical probes FIRST, then (if the
    structural probes pass) the suite against the LIVE model, persisting an
    immutable qualification run. Inference is gated exactly like `models probe`."""
    import asyncio as _asyncio
    from pathlib import Path

    from .qualification import build_run, load_corpus

    if model:
        from .admission import ensure_profile, parse_model_ref, qualify_live
        from .errors import ProtectedActionError
        from .probing import InferenceAuthorization, probe_gates_pass, run_probe_suite

        provider_id, model_id = parse_model_ref(model)
        auth = InferenceAuthorization(
            allow_inference=allow_inference,
            allow_subscription_inference=allow_subscription_inference,
            allow_paid_inference=allow_paid_inference,
            max_cost_usd=max_cost_usd,
        )
        with _ctx() as ctx:
            profile = ensure_profile(ctx, provider_id, model_id)
            console.print(f"profile: [bold]{profile.profile_id}[/]")
            try:
                probe = _asyncio.run(run_probe_suite(ctx, profile, auth=auth))
                console.print(f"probes: {probe.passed}/{probe.total} passed ({probe.run_id})")
                if not probe_gates_pass(probe):
                    console.print(
                        "[yellow]structural probes failed; skipping qualification "
                        "(model is not fit for semantic work)[/]"
                    )
                    raise typer.Exit(code=0)
                run = _asyncio.run(qualify_live(ctx, profile, auth=auth, probe_run_id=probe.run_id))
            except ProtectedActionError as exc:
                console.print(f"[yellow]{exc}[/]")
                raise typer.Exit(code=0) from None
        console.print(
            f"live qualification {run.run_id}: {run.cases_passed}/{run.cases_total} passed; "
            f"evidence roles: {[r.value for r in run.roles_admitted]}; "
            f"run 'models admit {profile.profile_id}' to admit"
        )
        return

    with _ctx() as ctx:
        suite = load_corpus(
            Path(ctx.config.qualification.corpus_dir), Path(ctx.config.qualification.holdout_dir)
        )
        # Reference answers => proves graders + admission logic run end-to-end.
        answers = {}
        for c in suite.cases:
            g = c.grader
            if g in ("choice", "exact", "contains"):
                answers[c.case_id] = str(c.expected.get("value", ""))
            elif g == "iri_exact":
                answers[c.case_id] = c.expected.get("iri", "")
            elif g == "uncertainty":
                answers[c.case_id] = "I do not know; insufficient evidence."
        run = build_run(
            agent_profile_id="self-check", suite=suite, answers=answers, trust=ctx.config.trust
        )
    console.print(
        f"qualification self-check: {run.cases_passed}/{run.cases_total} graded; "
        f"roles from reference answers: {[r.value for r in run.roles_admitted]} "
        f"(self-check; not stored as model evidence)"
    )


@models_app.command("admit")
def models_admit(
    profile_id: str = typer.Argument(..., help="agent profile id"),
    role: str = typer.Option(None, "--role", help="explicit role grant (needs override flag)"),
    operator_override: bool = typer.Option(
        False, "--operator-override", help="record an explicit operator role grant"
    ),
) -> None:
    """Compute admitted roles from STORED qualification evidence (default), or
    record an explicit operator override grant of one role."""
    from .admission import admit_from_evidence, grant_role_operator_override
    from .enums import AdmissionRole

    with _ctx() as ctx:
        if role:
            if not operator_override:
                err.print(
                    "[red]an explicit --role grant bypasses evidence-computed admission; "
                    "pass --operator-override to record it as an operator decision[/]"
                )
                raise typer.Exit(code=1)
            roles = grant_role_operator_override(ctx, profile_id, AdmissionRole(role))
            console.print(f"operator override recorded; roles now: {[r.value for r in roles]}")
            return
        roles = admit_from_evidence(ctx, profile_id)
    console.print(f"roles computed from qualification evidence: {[r.value for r in roles]}")


@models_app.command("evaluate-providers")
def models_evaluate_providers(
    allow_inference: bool = typer.Option(False, "--allow-inference"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    allow_paid_inference: bool = typer.Option(False, "--allow-paid-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd"),
    concurrency: int = typer.Option(4, "--concurrency"),
    provider_timeout_s: float = typer.Option(180.0, "--provider-timeout-s"),
    force: bool = typer.Option(False, "--force"),
    report: str = typer.Option("docs/provider-evaluation-report.md", "--report"),
) -> None:
    """Single provider-coverage pass: one representative model per CONFIGURED
    provider (every provider gets exactly one row), one compact semantic
    evaluation, bounded concurrency, continue-on-failure. Paid inference is never
    invoked without --allow-paid-inference."""
    import asyncio as _asyncio

    from .provider_eval import EvalAuth, evaluate_all_providers
    from .selection_report import build_and_persist_roster, render_coverage_report, write_report

    auth = EvalAuth(
        allow_inference=allow_inference,
        allow_subscription_inference=allow_subscription_inference,
        allow_paid_inference=allow_paid_inference,
        max_cost_usd=max_cost_usd,
    )
    with _ctx() as ctx:
        evals = _asyncio.run(
            evaluate_all_providers(ctx, auth, concurrency=concurrency, force=force)
        )
        roster = build_and_persist_roster(ctx, evals)
        md = render_coverage_report(evals, roster)
        path = write_report(md, report)
    t = Table(title=f"provider coverage ({len(evals)} rows)")
    for col in ("provider", "model", "actual", "status", "fidelity", "opt", "transport"):
        t.add_column(col)
    for e in sorted(evals, key=lambda x: x.provider_id):
        caps = e.adapter_capabilities or {}
        transport = (
            "brokered"
            if caps.get("brokered_tool_loop")
            else ("bounded" if caps.get("bounded_patch_synthesis") else "-")
        )
        t.add_row(
            e.provider_id,
            (e.requested_model or "-")[-22:],
            (e.actual_model or "-")[-18:] if e.actual_model else "unverified",
            e.status,
            f"{e.semantic_scores.get('semantic_rule_fidelity', 0):.2f}"
            if e.semantic_scores
            else "-",
            f"{e.semantic_scores.get('semantic_optimization', 0):.2f}"
            if e.semantic_scores
            else "-",
            transport,
        )
    console.print(t)
    paid = sum(e.paid_api_spend_usd for e in evals)
    sub = sum(e.subscription_reported_value_usd for e in evals)
    console.print(
        f"paid API spend: ${paid:.2f}  | subscription reported value: ${sub:.4f} (informational)"
    )
    console.print(f"[green]report written:[/] {path}")


# Assessment order: subscription CLIs, then metadata-cheap external non-Llama.
_ASSESS_ORDER = [
    "codex-cli",
    "claude-cli",
    "gemini",
    "mistral",
    "deepseek",
    "openrouter",
    "openai-api",
    "groq",
    "cerebras",
    "sambanova",
    "fireworks",
    "together",
    "huggingface",
    "arcee",
]


@models_app.command("assess")
def models_assess(
    exclude_provider: list[str] = typer.Option([], "--exclude-provider"),
    exclude_model: list[str] = typer.Option([], "--exclude-model"),
    exclude_family: list[str] = typer.Option([], "--exclude-family"),
    include_model: list[str] = typer.Option([], "--include-model"),
    only_model: list[str] = typer.Option(
        [], "--models", help="assess ONLY these provider/model ids"
    ),
    force_reassess: bool = typer.Option(False, "--force-reassess"),
    skip_valid_existing: bool = typer.Option(
        True, "--skip-valid-existing/--no-skip-valid-existing"
    ),
    allow_inference: bool = typer.Option(False, "--allow-inference"),
    allow_subscription_inference: bool = typer.Option(False, "--allow-subscription-inference"),
    allow_paid_inference: bool = typer.Option(False, "--allow-paid-inference"),
    max_cost_usd: float = typer.Option(0.0, "--max-cost-usd"),
    repeats: int = typer.Option(2, "--repeats", help="probe rounds per model (LCB evidence)"),
    max_models: int = typer.Option(12, "--max-models"),
    admit: bool = typer.Option(False, "--admit", help="admit qualified models from evidence"),
    report: str = typer.Option(
        "docs/provider-model-selection-report.md", "--report", help="report output path"
    ),
) -> None:
    """Staged non-Llama provider/model tournament -> ranked roster + report.

    Defaults exclude ollama + the llama family and skip models with valid
    evidence. Inference is gated exactly like `models probe`."""
    import asyncio as _asyncio

    from .probing import InferenceAuthorization
    from .selection import (
        SelectionFilters,
        default_filters,
        run_tournament,
        select_roster,
    )

    base = default_filters()
    filters = SelectionFilters(
        exclude_providers=sorted(set(base.exclude_providers) | set(exclude_provider)),
        exclude_models=sorted(set(base.exclude_models) | set(exclude_model)),
        exclude_families=sorted(set(base.exclude_families) | set(exclude_family)),
        include_models=list(include_model),
        only_models=list(only_model),
        force_reassess=force_reassess,
        skip_valid_existing=skip_valid_existing,
    )
    auth = InferenceAuthorization(
        allow_inference=allow_inference,
        allow_subscription_inference=allow_subscription_inference,
        allow_paid_inference=allow_paid_inference,
        max_cost_usd=max_cost_usd,
    )
    with _ctx() as ctx:
        res = _asyncio.run(
            run_tournament(
                ctx, filters, auth=auth, order=_ASSESS_ORDER, repeats=repeats, max_models=max_models
            )
        )
        roster = select_roster(res.assessments)
        from .selection_report import render_report, write_report

        md = render_report(res, roster, filters)
        path = write_report(md, report)
        if admit:
            import contextlib

            from .admission import admit_from_evidence

            for a in res.assessments:
                if a.role_scores:
                    with contextlib.suppress(Exception):
                        admit_from_evidence(ctx, a.profile_id)
    t = Table(
        title=f"assessment ({len(res.assessments)} models; skipped {len(res.skipped_existing)})"
    )
    for col in ("provider", "model", "probes", "class", "roles(LCB>0)"):
        t.add_column(col)
    for a in res.assessments:
        t.add_row(
            a.provider_id,
            a.model_id[-26:],
            f"{a.probe_passed}/{a.probe_total}",
            a.classification,
            ",".join(sorted(a.role_scores)) or "-",
        )
    console.print(t)
    console.print(f"budget: spent ${res.budget_spent} / cap ${res.budget_total}")
    console.print(
        Panel(
            str({k: v.get("provider", v.get("status")) for k, v in roster.items()}),
            title="proposed roster",
        )
    )
    console.print(f"[green]report written:[/] {path}")


@models_app.command("profiles")
def models_profiles() -> None:
    """List persisted agent profiles with their qualification/admission facts."""
    from .admission import list_profiles

    with _ctx() as ctx:
        rows = list_profiles(ctx)
    table = Table(title=f"agent profiles ({len(rows)})")
    for col in ("profile", "provider", "model", "adapter", "roles", "cases"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["profile_id"][:20],
            r["provider_id"],
            r["model"],
            r["adapter"],
            ",".join(r["roles"]) or "-",
            r["cases"],
        )
    console.print(table)
    if not rows:
        console.print("[dim]no profiles yet: use 'models probe <provider/model>'[/]")


@models_app.command("leaderboard")
def models_leaderboard(
    task: str = typer.Option(..., "--task", help="task class"),
    dimension: str = typer.Option("implementation", "--dimension"),
) -> None:
    """Show the task-specific model leaderboard."""
    from .learning import LearningEngine

    with _ctx() as ctx:
        scores = LearningEngine(ctx.store).leaderboard(task, dimension)
    table = Table(title=f"leaderboard: {task} / {dimension}")
    for col in ("agent", "mean", "n", "ci_low", "ci_high"):
        table.add_column(col)
    for s in scores[:25]:
        table.add_row(
            s.agent_profile_id, f"{s.mean:.3f}", str(s.n), f"{s.ci_low:.3f}", f"{s.ci_high:.3f}"
        )
    console.print(table)
    if not scores:
        console.print("[dim]no scores yet (qualification/execution not run)[/]")


@models_app.command("show")
def models_show(agent_profile_id: str) -> None:
    """Show a stored agent profile and its qualification run."""
    with _ctx() as ctx:
        profile = ctx.store.get("agent_profiles", agent_profile_id)
        runs = ctx.store.records("qualification_runs", "agent_profile_id=?", (agent_profile_id,))
    if not profile:
        err.print(f"[red]no agent profile {agent_profile_id}[/]")
        raise typer.Exit(code=1)
    console.print(Panel(str(profile), title="agent profile"))
    for r in runs:
        console.print(
            Panel(
                f"roles: {r.get('roles_admitted')}\nscores: {r.get('dimension_scores')}",
                title="qualification run",
            )
        )


# --------------------------------------------------------------------------- #
# usf
# --------------------------------------------------------------------------- #


@usf_app.command("health")
def usf_health() -> None:
    """Read-only USF MCP health."""
    from .authority import UsfAuthorityClient

    try:
        with UsfAuthorityClient() as c:
            tools = c.list_tools()
            h = c.health()
            console.print(Panel(secrets.redact(h.text()) or "(no text)", title="usf_health"))
            console.print(f"tools ({len(tools)}): {sorted(tools)}")
            console.print(f"resources (expected empty): {c.list_resources()}")
    except Exception as exc:
        err.print(f"[red]USF MCP unavailable: {exc}[/]")
        raise typer.Exit(code=1) from None


@usf_app.command("bootstrap")
def usf_bootstrap() -> None:
    """Read-only USF bootstrap summary (compact; no full transcript)."""
    from .authority import UsfAuthorityClient

    with UsfAuthorityClient() as c:
        b = c.bootstrap().json() or {}
    auth = b.get("authority", {}) if isinstance(b, dict) else {}
    body = (
        f"authorityDigest: {auth.get('digest', '?')}\n"
        f"triples: {auth.get('triples')}  graphs: {auth.get('coveredGraphCount')}\n"
        f"openGaps: {len(b.get('openGaps') or [])}  "
        f"proofObligations: {len(b.get('proofObligations') or [])}  "
        f"validationObligations: {len(b.get('validationObligations') or [])}"
    )
    console.print(Panel(secrets.redact(body), title="usf_bootstrap (compact)"))


# --------------------------------------------------------------------------- #
# cycle
# --------------------------------------------------------------------------- #


@cycle_app.command("snapshot")
def cycle_snapshot() -> None:
    """Compile a deterministic semantic snapshot (read-only)."""
    from .engine import FactoryEngine

    with _ctx() as ctx:
        eng = FactoryEngine(ctx)
        eng.preflight("adhoc")
        snap = eng.capture_snapshot("adhoc")
    body = (
        f"snapshotId: {snap.snapshot_id}\n"
        f"authorityDigest: {snap.authority_digest}\n"
        f"repositoryHead: {snap.repository_head}\n"
        f"triples: {snap.triple_count}  graphs: {snap.graph_count}\n"
        f"unresolvedObligations: {len(snap.unresolved_obligations)}\n"
        f"activePhase: {snap.active_phase}\n"
        f"mcpTools: {len(snap.mcp_tools)}  healthOk: {snap.health_ok}"
    )
    console.print(Panel(secrets.redact(body), title="semantic snapshot"))


@cycle_app.command("plan")
def cycle_plan() -> None:
    """Produce an obligation graph + packet set (plan-only; no writes)."""
    from .engine import FactoryEngine

    async def _go(ctx: RuntimeContext):
        eng = FactoryEngine(ctx)
        eng.preflight("adhoc")
        snap = eng.capture_snapshot("adhoc")
        return snap, *await eng.plan_and_compile(snap, "adhoc")

    with _ctx() as ctx:
        snap, _graph, pset, findings = asyncio.run(_go(ctx))
    table = Table(title="packets")
    for col in ("obligation", "task_class", "risk", "selected"):
        table.add_column(col)
    sel = set(pset.selected_packet_ids)
    for p in pset.packets:
        table.add_row(
            p.obligation_id,
            p.task_class,
            p.risk.value,
            "[green]yes[/]" if p.packet_id in sel else "[dim]deferred[/]",
        )
    console.print(table)
    console.print(f"snapshot={snap.snapshot_id} set={pset.set_id}")
    if findings:
        console.print(
            Panel("\n".join(f"- {f}" for f in findings), title="planner/compiler findings")
        )


@cycle_app.command("show")
def cycle_show(cycle_id: str | None = typer.Argument(None)) -> None:
    """Show a cycle receipt (latest if not specified)."""
    with _ctx() as ctx:
        items = sorted(ctx.store.items("cycles"), key=lambda t: t[0])
        if not items:
            console.print("[dim]no cycles yet[/]")
            return
        target = None
        if cycle_id:
            target = next((c for cid, c in items if cid == cycle_id), None)
        else:
            target = items[-1][1]
    if not target:
        err.print(f"[red]cycle {cycle_id} not found[/]")
        raise typer.Exit(code=1)
    console.print(Panel(secrets.redact(str(target)), title="cycle"))


@cycle_app.command("status")
def cycle_status() -> None:
    """Alias for top-level status."""
    status()


# --------------------------------------------------------------------------- #
# maintenance
# --------------------------------------------------------------------------- #


@maint_app.command("backup")
def maintenance_backup(dest: str = typer.Argument(..., help="destination .sqlite path")) -> None:
    """Consistent online backup of the state database."""
    from pathlib import Path

    with _ctx() as ctx:
        ctx.store.backup(Path(dest))
    console.print(f"[green]backed up state to {dest}[/]")


@maint_app.command("gc")
def maintenance_gc() -> None:
    """Garbage-collect unreferenced content-addressed artifacts."""
    with _ctx() as ctx:
        removed = ctx.store.cas_gc()
    console.print(f"[green]removed {removed} unreferenced CAS blob(s)[/]")


# --------------------------------------------------------------------------- #
# materialisation
# --------------------------------------------------------------------------- #


def _build_index(ctx=None):
    """Snapshot-bound build from the factory mirror at the current USF head, with
    stored ownership evidence applied (verified owners marked)."""
    from .isolation import RepoIsolation
    from .materialisation import build_index_at
    from .ownership import verify_index

    def _go(c):
        iso = RepoIsolation(c.paths, c.usf_repo)
        iso.ensure_mirror()
        idx = build_index_at(c.paths.mirror, iso.usf_head())
        verify_index(c, idx)
        return idx

    if ctx is not None:
        return _go(ctx)
    with _ctx() as c:
        return _go(c)


@mat_app.command("build")
def materialisation_build() -> None:
    """Build the subject->materialisation index from the factory mirror at the
    current USF head (read-only; snapshot-bound; ownership evidence applied)."""
    idx = _build_index()
    console.print(
        Panel(
            f"version: {idx.index_version}\nsource_digest: {idx.source_digest}\n"
            f"source_commit: {idx.source_commit}\nsnapshot_bound: {idx.snapshot_bound}\n"
            f"subjects indexed: {len(idx.entries)}\n"
            f"candidate owners: {len(idx.candidates())}\n"
            f"verified owners: {len(idx.verified())}",
            title="materialisation index",
        )
    )


@mat_app.command("candidates")
def materialisation_candidates(limit: int = typer.Option(40, "--limit")) -> None:
    """List subjects with a CANDIDATE (parsed, unverified) owner. These may NOT
    authorize a semantic write until verified via evidence or `approve`."""
    idx = _build_index()
    cands = idx.candidates()
    table = Table(title=f"candidate owners ({len(cands)}) — NOT write-authorizing")
    for col in ("subject", "candidate owner(s)", "method"):
        table.add_column(col)
    for e in cands[:limit]:
        table.add_row(e.subject[-48:], ", ".join(e.candidate_owners)[:60], e.method)
    console.print(table)


@mat_app.command("verify")
def materialisation_verify(limit: int = typer.Option(40, "--limit")) -> None:
    """List subjects with a VERIFIED (evidence-backed) owner — the only ones that
    may authorize a semantic write scope."""
    idx = _build_index()
    ver = idx.verified()
    table = Table(title=f"verified owners ({len(ver)})")
    for col in ("subject", "verified owner", "evidence"):
        table.add_column(col)
    for e in ver[:limit]:
        table.add_row(e.subject[-48:], e.verified_owner or "-", e.verification_kind or "-")
    console.print(table)


@mat_app.command("approve")
def materialisation_approve(
    subject: str = typer.Argument(..., help="semantic subject IRI"),
    path: str = typer.Option(..., "--path", help="repository owner path"),
) -> None:
    """Record an append-only, digest-bound OPERATOR ownership approval binding a
    subject to exactly one owner path (verifies a candidate)."""
    from .errors import ConfigError
    from .ownership import approve_cli

    with _ctx() as ctx:
        try:
            ev = approve_cli(ctx, subject, path)
        except ConfigError as exc:
            err.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from None
    console.print(
        f"[green]approved[/] {subject} -> {path} "
        f"(evidence {ev.evidence_id}, commit {ev.repository_commit})"
    )


@mat_app.command("describe")
def materialisation_describe(iri: str) -> None:
    """Describe the materialisation surface of a semantic subject IRI."""
    e = _build_index().resolve(iri)
    if e is None:
        err.print(f"[yellow]no mapping for {iri}[/]")
        raise typer.Exit(code=1)
    console.print(
        Panel(
            f"candidate owners: {e.candidate_owners}\n"
            f"verified owner: {e.verified_owner}  ({e.verification_kind or 'unverified'})\n"
            f"method: {e.method}  verified: {e.verified}  conf: {e.confidence}\n"
            f"shapes: {e.shapes}\nrules: {e.rules}\ntests: {e.tests}\n"
            f"generated: {e.generated_outputs}\nvalidation: {e.validation_profiles}",
            title=iri,
        )
    )


@mat_app.command("affected-by")
def materialisation_affected_by(path: str) -> None:
    """List semantic subjects materialised (partly) by a repository path."""
    subjects = _build_index().affected_by(path)
    console.print("\n".join(subjects) or "[dim]none[/]")


# --------------------------------------------------------------------------- #
# routing
# --------------------------------------------------------------------------- #


@app.command("routing")
def routing_explain(
    action: str = typer.Argument(..., help="'explain'"),
    packet_id: str = typer.Argument(..., help="packet id"),
) -> None:
    """Explain a routing decision: `usf-factory routing explain <packet-id>`."""
    if action != "explain":
        err.print("usage: usf-factory routing explain <packet-id>")
        raise typer.Exit(code=2)
    with _ctx() as ctx:
        rows = ctx.store.records("routing_decisions", "packet_id=?", (packet_id,))
    if not rows:
        err.print(f"[yellow]no routing decision for {packet_id}[/]")
        raise typer.Exit(code=1)
    d = rows[-1]
    console.print(
        Panel(
            f"selected: {d.get('selected_profile_id')}\nkind: {d.get('selection_kind')}\nrole: {d.get('role')}\nseed: {d.get('seed')}",
            title=f"routing {packet_id}",
        )
    )
    table = Table(title="candidates")
    for col in ("agent", "eligible", "score", "reasons"):
        table.add_column(col)
    for c in d.get("candidates", []):
        table.add_row(
            c.get("agent_profile_id", ""),
            "yes" if c.get("eligible") else "no",
            f"{c.get('score', 0):.4f}",
            ", ".join(c.get("exclusion_reasons", []))[:60],
        )
    console.print(table)


if __name__ == "__main__":
    app()
