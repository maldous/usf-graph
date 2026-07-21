"""`usf-factory doctor` — environment, config, isolation, and safety self-check.

Reports only names/counts/booleans — never a credential value.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from . import secrets
from .context import RuntimeContext
from .enums import ProtectedAction
from .isolation import RepoIsolation

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class DoctorCheck:
    name: str
    status: str
    detail: str


def run_doctor(ctx: RuntimeContext, *, check_mcp: bool = True) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []

    # Python.
    v = sys.version_info
    checks.append(
        DoctorCheck(
            "python",
            OK if (v.major, v.minor) >= (3, 11) else FAIL,
            f"{v.major}.{v.minor}.{v.micro}",
        )
    )

    # Config.
    try:
        n_providers = len(ctx.config.providers.providers)
        checks.append(DoctorCheck("config", OK, f"{n_providers} providers configured"))
    except Exception as exc:
        checks.append(DoctorCheck("config", FAIL, str(exc)))

    # Codebuff must be absent.
    ids = {p.provider_id for p in ctx.config.providers.providers}
    checks.append(
        DoctorCheck(
            "codebuff-excluded",
            OK if "codebuff" not in ids else FAIL,
            "absent" if "codebuff" not in ids else "PRESENT — must be removed",
        )
    )

    # Isolation directories.
    p = ctx.paths
    missing = [
        str(d) for d in (p.share, p.state, p.cache, p.workspaces, p.integration) if not d.exists()
    ]
    checks.append(
        DoctorCheck(
            "isolation-dirs",
            OK if not missing else FAIL,
            "present" if not missing else f"missing: {missing}",
        )
    )

    # Secret file presence + mode.
    if ctx.env_file.exists():
        mode = oct(ctx.env_file.stat().st_mode & 0o777)
        status = OK if mode == "0o600" else WARN
        checks.append(
            DoctorCheck(
                "env-file",
                status,
                f"{ctx.env_file} mode {mode}"
                + ("" if status == OK else " (expected 0600; run import-provider-env.py)"),
            )
        )
    else:
        checks.append(
            DoctorCheck("env-file", WARN, f"{ctx.env_file} absent (no credentials imported)")
        )

    # Credentials present by NAME/count only.
    allow = secrets.load_allowlisted_env(ctx.env_file)
    checks.append(
        DoctorCheck(
            "credentials",
            OK if allow else WARN,
            f"{len(allow)} allowlisted model-provider variables present (names withheld here)",
        )
    )

    # Excluded credentials must not be in the env file.
    raw = secrets.load_env_file(ctx.env_file)
    excluded_present = sorted(set(raw) & secrets.EXCLUDED_VARS)
    checks.append(
        DoctorCheck(
            "no-excluded-secrets",
            OK if not excluded_present else FAIL,
            "clean" if not excluded_present else f"excluded vars present: {excluded_present}",
        )
    )

    # Provider enablement summary.
    try:
        from .providers import build_registry

        reg = build_registry(ctx)
        enabled = reg.enabled_ids()
        checks.append(DoctorCheck("providers-enabled", OK, f"{len(enabled)} enabled: {enabled}"))
    except Exception as exc:
        checks.append(DoctorCheck("providers-enabled", FAIL, str(exc)))

    # Isolation: /usf readable, no factory worktrees, mirror present.
    iso = RepoIsolation(ctx.paths, ctx.usf_repo)
    try:
        head = iso.usf_head()
        stray = iso.assert_no_factory_worktrees()
        checks.append(
            DoctorCheck(
                "usf-isolation",
                OK if not stray else FAIL,
                f"/usf HEAD {head[:12]}; factory worktrees: {stray or 'none'}",
            )
        )
    except Exception as exc:
        checks.append(DoctorCheck("usf-isolation", WARN, f"/usf not inspectable: {exc}"))
    checks.append(
        DoctorCheck(
            "mirror",
            OK if iso.mirror_exists() else WARN,
            "present" if iso.mirror_exists() else "absent (created on first cycle)",
        )
    )

    # Safety gates — all must be disabled by default.
    gates = {a.value: ctx.is_gate_enabled(a) for a in ProtectedAction}
    enabled_gates = [k for k, v in gates.items() if v]
    checks.append(
        DoctorCheck(
            "protected-gates",
            OK if not enabled_gates else WARN,
            "all disabled" if not enabled_gates else f"ENABLED: {enabled_gates}",
        )
    )
    checks.append(
        DoctorCheck(
            "autonomous-safe",
            OK,
            "enabled" if ctx.config.safety.autonomous_safe_enabled else "disabled (default)",
        )
    )

    # MCP health (read-only).
    if check_mcp:
        try:
            from .authority import UsfAuthorityClient

            with UsfAuthorityClient() as c:
                tools = c.list_tools()
                h = c.health()
                hj = h.json() or {}
                ok = bool(hj.get("ok", h.ok))
                checks.append(
                    DoctorCheck(
                        "usf-mcp",
                        OK if ok else WARN,
                        f"health ok={ok}; {len(tools)} tools; triples={hj.get('triples')}",
                    )
                )
        except Exception as exc:
            checks.append(DoctorCheck("usf-mcp", WARN, f"unavailable: {type(exc).__name__}"))
    else:
        checks.append(DoctorCheck("usf-mcp", WARN, "skipped"))

    return checks


def overall_status(checks: list[DoctorCheck]) -> str:
    if any(c.status == FAIL for c in checks):
        return FAIL
    if any(c.status == WARN for c in checks):
        return WARN
    return OK
