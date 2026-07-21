"""OIDC / CLI adapters for Codex and Claude.

These use the operator's EXISTING CLI authentication. They never read, print, or
copy OAuth/OIDC tokens or session material. Auth is probed only via supported
CLI invocations and read-only existence checks of auth directories (never their
contents). This module never modifies ~/.codex or ~/.claude.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from pathlib import Path

from ..enums import HealthStatus, Modality
from ..models import (
    AgentRequest,
    AgentResponse,
    DiscoveredModel,
    ProbeResult,
    ProbeSpec,
    ProviderConfig,
    ProviderHealth,
)
from .base import AdapterError

# Only these variables are forwarded to CLI subprocesses. API-provider keys and
# every other secret are deliberately withheld so an OIDC CLI (Codex/Claude)
# never inherits credentials it must not see.
_SAFE_ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR")


def _sanitized_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}


async def _run(
    cmd: list[str], timeout_s: float = 10.0, stdin: str | None = None
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_sanitized_env(),
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout_s
        )
    except TimeoutError:
        proc.kill()
        return (124, "", "timeout")
    return (proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace"))


class _CliAdapterBase:
    binary: str = ""
    auth_dirs: tuple[Path, ...] = ()
    known_models: tuple[tuple[str, str], ...] = ()  # (model_id, display)

    def __init__(self, config: ProviderConfig, *, allow_billable: bool = False) -> None:
        self.config = config
        self.allow_billable = allow_billable

    def _binary_path(self) -> str | None:
        return shutil.which(self.binary)

    def _auth_material_present(self) -> bool:
        # Read-only existence check; never opens the files.
        return any(p.exists() for p in self.auth_dirs)

    async def discover_models(self) -> list[DiscoveredModel]:
        # CLI providers have no catalog API; return the curated known set as
        # dated claims. Availability is confirmed separately by probe_auth.
        return [
            DiscoveredModel(
                provider_id=self.config.provider_id,
                requested_model_id=mid,
                display_name=disp,
                modalities=[Modality.TEXT],
                claims_tools=True,
                claims_structured_output=True,
                claims_reasoning=True,
                free=None,
            )
            for mid, disp in self.known_models
        ]

    async def probe_auth(self) -> ProviderHealth:
        binpath = self._binary_path()
        if binpath is None:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.UNAVAILABLE,
                detail=f"{self.binary} not on PATH",
            )
        start = time.perf_counter()
        code, _out, _err = await _run([binpath, "--version"])
        latency = (time.perf_counter() - start) * 1000
        if code != 0:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.DEGRADED,
                detail=f"{self.binary} present but --version failed",
                latency_ms=latency,
            )
        if self._auth_material_present():
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.HEALTHY,
                detail="CLI present; auth material present (contents not read)",
                latency_ms=latency,
            )
        return ProviderHealth(
            provider_id=self.config.provider_id,
            status=HealthStatus.UNAUTHENTICATED,
            detail="CLI present; no auth material detected",
            latency_ms=latency,
        )

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        if not self.allow_billable:
            raise AdapterError(f"billable inference disabled for {self.config.provider_id}")
        raise AdapterError(f"{self.config.provider_id} probe_model not enabled in the safe runtime")

    # Subclasses build argv and parse stdout for their CLI's non-interactive mode.
    def _argv(self, binpath: str, model_id: str, prompt: str) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def _parse_output(self, stdout: str) -> str:  # pragma: no cover
        raise NotImplementedError

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        # Billable: uses the operator's existing CLI subscription/auth. Gated.
        if not self.allow_billable:
            raise AdapterError(f"billable inference disabled for {self.config.provider_id}")
        binpath = self._binary_path()
        if binpath is None:
            raise AdapterError(f"{self.binary} not on PATH")
        model_id = request.model_id_for("default")
        # Runs as the current (authenticated) user with a SANITIZED env — the CLI
        # needs HOME for its OIDC auth but must never see API-provider keys.
        code, out, err = await _run(
            self._argv(binpath, model_id, request.instructions), timeout_s=float(request.max_wall_s)
        )
        if code != 0:
            raise AdapterError(f"{self.config.provider_id} exited {code}: {err.strip()[:200]}")
        text = self._parse_output(out)
        return AgentResponse(
            agent_profile_id=request.agent_profile_id,
            actual_provider=self.config.provider_id,
            actual_model=model_id,
            output_text=text,
        )


class CodexCliAdapter(_CliAdapterBase):
    binary = "codex"
    auth_dirs = (Path.home() / ".codex" / "auth.json", Path.home() / ".codex")
    known_models = (
        ("gpt-5-codex", "GPT-5 Codex (via Codex CLI)"),
        ("gpt-5", "GPT-5 (via Codex CLI)"),
        ("o4-mini", "o4-mini (via Codex CLI)"),
    )

    def _argv(self, binpath: str, model_id: str, prompt: str) -> list[str]:
        # Non-interactive, ephemeral, JSON event stream (build task §5 refs).
        return [binpath, "exec", "--json", "--skip-git-repo-check", "-m", model_id, prompt]

    def _parse_output(self, stdout: str) -> str:
        # Codex emits JSONL events; return the last agent/assistant text.
        text = ""
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = ev.get("message") or ev.get("text") or ev.get("content")
            if isinstance(msg, str) and msg:
                text = msg
            elif ev.get("type") in ("agent_message", "assistant") and isinstance(
                ev.get("delta"), str
            ):
                text += ev["delta"]
        return text or stdout.strip()


class ClaudeCliAdapter(_CliAdapterBase):
    binary = "claude"
    auth_dirs = (
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude",
        Path.home() / ".config" / "claude",
    )
    known_models = (
        ("claude-opus-4-8", "Claude Opus 4.8 (via Claude CLI)"),
        ("claude-sonnet-5", "Claude Sonnet 5 (via Claude CLI)"),
        ("claude-haiku-4-5", "Claude Haiku 4.5 (via Claude CLI)"),
    )

    def _argv(self, binpath: str, model_id: str, prompt: str) -> list[str]:
        return [binpath, "--print", "--output-format", "json", "--model", model_id, prompt]

    def _parse_output(self, stdout: str) -> str:
        # Claude Code print mode returns a JSON object with a "result" field.
        try:
            obj = json.loads(stdout)
        except json.JSONDecodeError:
            return stdout.strip()
        if isinstance(obj, dict):
            return str(obj.get("result") or obj.get("content") or "")
        return stdout.strip()
