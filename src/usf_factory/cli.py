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
app.add_typer(env_app, name="env")
app.add_typer(providers_app, name="providers")
app.add_typer(models_app, name="models")
app.add_typer(usf_app, name="usf")
app.add_typer(cycle_app, name="cycle")
app.add_typer(maint_app, name="maintenance")


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
    mode: str = typer.Option("plan-only", "--mode", help="observe | plan-only | autonomous-safe"),
) -> None:
    """Run one cycle in the given mode (observe/plan-only are non-mutating)."""
    try:
        run_mode = RunMode(mode)
    except ValueError:
        err.print(f"[red]unknown mode '{mode}'. Use observe | plan-only | autonomous-safe.[/]")
        raise typer.Exit(code=2) from None
    from .engine import FactoryEngine

    with _ctx() as ctx:
        if (ctx.paths.state / "PAUSED").exists():
            err.print("[yellow]factory is paused; run `usf-factory resume` first[/]")
            raise typer.Exit(code=1)
        eng = FactoryEngine(ctx)
        receipt = asyncio.run(eng.run_cycle(run_mode))
    _print_receipt(receipt)


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
    allow_billable: bool = typer.Option(False, "--allow-billable"),
    budget_usd: float = typer.Option(0.0, "--budget-usd"),
) -> None:
    """Run mechanical probes (billable; disabled by default)."""
    if not allow_billable or budget_usd <= 0:
        err.print("[yellow]mechanical probes require --allow-billable and --budget-usd > 0[/]")
        err.print(
            "provider discovery and auth probes are available without billing via `providers refresh`."
        )
        raise typer.Exit(code=1)
    err.print("[yellow]billable probing is not enabled in this safe runtime build.[/]")
    raise typer.Exit(code=1)


@models_app.command("qualify")
def models_qualify(
    allow_billable: bool = typer.Option(False, "--allow-billable"),
    budget_usd: float = typer.Option(0.0, "--budget-usd"),
) -> None:
    """Run the USF qualification suite (billable; disabled by default)."""
    if not allow_billable or budget_usd <= 0:
        err.print("[yellow]qualification requires --allow-billable and --budget-usd > 0[/]")
        raise typer.Exit(code=1)
    err.print("[yellow]billable qualification is not enabled in this safe runtime build.[/]")
    raise typer.Exit(code=1)


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
