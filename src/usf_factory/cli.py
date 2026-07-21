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
) -> None:
    """Run one cycle in the given mode (observe/plan-only are non-mutating)."""
    try:
        run_mode = RunMode(mode)
    except ValueError:
        err.print(
            f"[red]unknown mode '{mode}'. Use observe | plan-only | shadow | approve-wave | autonomous-safe.[/]"
        )
        raise typer.Exit(code=2) from None
    from .runtime import build_engine

    with _ctx() as ctx:
        if (ctx.paths.state / "PAUSED").exists():
            err.print("[yellow]factory is paused; run `usf-factory resume` first[/]")
            raise typer.Exit(code=1)
        # Fully-wired production engine (worker factory + materialisation index).
        eng = build_engine(ctx, mode=run_mode)
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
    model: str = typer.Argument(None, help="provider/model to create a profile for"),
    allow_billable: bool = typer.Option(False, "--allow-billable"),
    budget_usd: float = typer.Option(0.0, "--budget-usd"),
) -> None:
    """Run the mechanical probe graders. With a provider/model argument, the
    AgentProfile is created/persisted (the admission entry point). A zero-cost
    self-check grades the probe specs against reference answers (proving the
    graders execute); live model probing additionally requires --allow-billable
    + budget and never records fabricated results."""
    from .probes import default_probe_specs, grade_probe

    if model:
        from .admission import ensure_profile, parse_model_ref

        provider_id, model_id = parse_model_ref(model)
        with _ctx() as ctx:
            profile = ensure_profile(ctx, provider_id, model_id)
        console.print(
            f"profile persisted: [bold]{profile.profile_id}[/] "
            f"({provider_id}/{model_id}, adapter={profile.adapter})"
        )

    specs = default_probe_specs()
    # Self-check: grade each probe against a reference "correct" answer.
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
        r = grade_probe(s, ref)
        passed += 1 if r.passed else 0
    console.print(f"probe graders self-check: {passed}/{len(specs)} graders produced a verdict")
    if not (allow_billable and budget_usd > 0):
        console.print(
            "[yellow]live model probing requires --allow-billable and --budget-usd > 0[/]"
        )
        return
    console.print(
        "[yellow]no zero-cost live model reachable here (ENVIRONMENT_BLOCKED); "
        "live probing not performed[/]"
    )


@models_app.command("qualify")
def models_qualify(
    model: str = typer.Argument(None, help="provider/model to qualify LIVE (billable; gated)"),
    allow_billable: bool = typer.Option(False, "--allow-billable"),
    budget_usd: float = typer.Option(0.0, "--budget-usd"),
) -> None:
    """Run the USF qualification suite.

    Without an argument: a zero-cost SELF-CHECK grades the corpus against
    reference answers (proving the scorer + admission logic execute). The
    self-check is never stored as model evidence.

    With provider/model: persists the AgentProfile and runs the suite against
    the LIVE model (billable; requires --allow-billable + budget). A gated run
    persists the profile only — no fabricated qualification evidence."""
    import asyncio as _asyncio
    from pathlib import Path

    from .qualification import build_run, load_corpus

    if model:
        from .admission import ensure_profile, parse_model_ref, qualify_live
        from .errors import ProtectedActionError

        provider_id, model_id = parse_model_ref(model)
        with _ctx() as ctx:
            profile = ensure_profile(ctx, provider_id, model_id)
            console.print(f"profile: [bold]{profile.profile_id}[/]")
            try:
                run = _asyncio.run(
                    qualify_live(ctx, profile, allow_billable=allow_billable, budget_usd=budget_usd)
                )
            except ProtectedActionError as exc:
                console.print(f"[yellow]{exc}[/]")
                console.print(
                    "[yellow]profile persisted; NO qualification evidence recorded "
                    "(live qualification is gated)[/]"
                )
                raise typer.Exit(code=0) from None
        console.print(
            f"live qualification: {run.cases_passed}/{run.cases_total} passed; "
            f"roles: {[r.value for r in run.roles_admitted]}"
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


def _build_index():
    """Snapshot-bound build: from the factory mirror at the current USF head
    (git object store — uncommitted /usf working-tree content can never leak in)."""
    from .isolation import RepoIsolation
    from .materialisation import build_index_at

    with _ctx() as ctx:
        iso = RepoIsolation(ctx.paths, ctx.usf_repo)
        iso.ensure_mirror()
        return build_index_at(ctx.paths.mirror, iso.usf_head())


@mat_app.command("build")
def materialisation_build() -> None:
    """Build the subject->materialisation index from the factory mirror at the
    current USF head (read-only; snapshot-bound)."""
    idx = _build_index()
    console.print(
        Panel(
            f"version: {idx.index_version}\nsource_digest: {idx.source_digest}\n"
            f"source_commit: {idx.source_commit}\nsnapshot_bound: {idx.snapshot_bound}\n"
            f"subjects indexed: {len(idx.entries)}\n"
            f"verified owners: {sum(1 for e in idx.entries.values() if e.verified)}",
            title="materialisation index",
        )
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
            f"owner: {e.owner_path}\nmethod: {e.method}  verified: {e.verified}  conf: {e.confidence}\n"
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
