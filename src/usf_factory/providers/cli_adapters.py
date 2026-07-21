"""OIDC / CLI adapters for Codex and Claude.

These use the operator's EXISTING CLI authentication. They never read, print, or
copy OAuth/OIDC tokens or session material. Auth is probed only via supported
CLI invocations and read-only existence checks of auth directories (never their
contents). This module never modifies ~/.codex or ~/.claude.
"""

from __future__ import annotations

import asyncio
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


async def _run(
    cmd: list[str], timeout_s: float = 10.0, stdin: str | None = None
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
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

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        if not self.allow_billable:
            raise AdapterError(f"billable inference disabled for {self.config.provider_id}")
        # Deliberately not wired to a live CLI call in the safe runtime. The
        # worker layer routes real CLI execution through the sandbox; see
        # workers.py. This method exists so the adapter satisfies the protocol.
        raise AdapterError(
            f"{self.config.provider_id} direct invoke is routed through the sandboxed worker"
        )


class CodexCliAdapter(_CliAdapterBase):
    binary = "codex"
    auth_dirs = (Path.home() / ".codex" / "auth.json", Path.home() / ".codex")
    known_models = (
        ("gpt-5-codex", "GPT-5 Codex (via Codex CLI)"),
        ("gpt-5", "GPT-5 (via Codex CLI)"),
        ("o4-mini", "o4-mini (via Codex CLI)"),
    )


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
