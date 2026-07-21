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
from typing import Any

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

    async def _cli_version(self) -> str:
        binpath = self._binary_path()
        if not binpath:
            return ""
        _c, out, _e = await _run([binpath, "--version"], timeout_s=15.0)
        return out.strip().splitlines()[0] if out.strip() else ""

    async def _exec(
        self, model_id: str, prompt: str, timeout_s: float
    ) -> tuple[str, Any, bool, str]:
        """Run the CLI non-interactively; return (text, TokenUsage, quota_blocked,
        error). Prompt is fed on stdin (CLIs read it there). Sanitized env — the
        CLI sees no API keys."""

        binpath = self._binary_path()
        if binpath is None:
            raise AdapterError(f"{self.binary} not on PATH")
        argv, stdin = self._argv(binpath, model_id, prompt)
        start = time.perf_counter()
        code, out, err = await _run(argv, timeout_s=timeout_s, stdin=stdin)
        wall = (time.perf_counter() - start) * 1000
        text, usage, quota = self._parse_full(out, err, code)
        usage.latency_ms = wall
        usage.actual_provider = self.config.provider_id
        if not usage.actual_model:
            usage.actual_model = model_id
        return text, usage, quota, (err.strip()[:200] if code != 0 else "")

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        """Genuine probe: invoke the CLI and grade the output with the canonical
        graders (never trust presence in a hard-coded list)."""
        if not self.allow_billable:
            raise AdapterError(
                f"subscription inference not authorized for {self.config.provider_id}"
            )
        from ..probes import grade_probe

        text, usage, quota, _err = await self._exec(model_id, probe.prompt, timeout_s=120.0)
        if quota:
            return ProbeResult(
                kind=probe.kind,
                version=probe.version,
                passed=False,
                detail="QUOTA_BLOCKED",
                actual_model_id=usage.actual_model,
                actual_provider=self.config.provider_id,
                usage=usage,
                latency_ms=usage.latency_ms,
            )
        result = grade_probe(probe, text, actual_model_id=usage.actual_model)
        return result.model_copy(
            update={
                "usage": usage,
                "actual_provider": self.config.provider_id,
                "latency_ms": usage.latency_ms,
            }
        )

    # Subclasses build argv (+ optional stdin) and parse stdout for their CLI.
    def _argv(
        self, binpath: str, model_id: str, prompt: str
    ) -> tuple[list[str], str | None]:  # pragma: no cover
        raise NotImplementedError

    def _parse_full(self, stdout: str, stderr: str, code: int) -> tuple[str, Any, bool]:
        """Return (text, TokenUsage, quota_blocked)."""  # pragma: no cover
        raise NotImplementedError

    def _parse_output(self, stdout: str) -> str:
        text, _u, _q = self._parse_full(stdout, "", 0)
        return text

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        # Billable: uses the operator's existing CLI subscription/auth. Gated.
        if not self.allow_billable:
            raise AdapterError(
                f"subscription inference not authorized for {self.config.provider_id}"
            )
        model_id = request.model_id_for("default")
        text, usage, quota, errmsg = await self._exec(
            model_id, request.instructions, timeout_s=float(request.max_wall_s)
        )
        if quota:
            raise AdapterError(f"{self.config.provider_id} QUOTA_BLOCKED")
        if errmsg and not text:
            raise AdapterError(f"{self.config.provider_id}: {errmsg}")
        return AgentResponse(
            agent_profile_id=request.agent_profile_id,
            actual_provider=self.config.provider_id,
            actual_model=usage.actual_model or model_id,
            output_text=text,
            tokens_in=usage.input_tokens or None,
            tokens_out=usage.output_tokens or None,
            cost_usd=usage.provider_reported_cost or 0.0,
            usage=usage,
            quota_blocked=quota,
        )


class CodexCliAdapter(_CliAdapterBase):
    binary = "codex"
    auth_dirs = (Path.home() / ".codex" / "auth.json", Path.home() / ".codex")
    known_models = (
        ("gpt-5-codex", "GPT-5 Codex (via Codex CLI)"),
        ("gpt-5", "GPT-5 (via Codex CLI)"),
        ("o4-mini", "o4-mini (via Codex CLI)"),
    )

    def _argv(self, binpath: str, model_id: str, prompt: str) -> tuple[list[str], str | None]:
        # Non-interactive, ephemeral, JSON event stream; prompt on stdin. The
        # account's default model is used unless an explicit model is requested
        # (a hard-coded model id that the account rejects is not "available").
        argv = [binpath, "exec", "--json", "--skip-git-repo-check"]
        if model_id and model_id != "default":
            argv += ["-m", model_id]
        argv += ["-"]
        return argv, prompt

    def _parse_full(self, stdout: str, stderr: str, code: int):
        from ..models import TokenUsage

        text = ""
        usage = TokenUsage()
        quota = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            typ = ev.get("type", "")
            item = ev.get("item") or {}
            if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                text = item["text"]
            elif typ == "agent_message" and isinstance(ev.get("message") or ev.get("text"), str):
                text = ev.get("message") or ev.get("text")
            elif isinstance(ev.get("text"), str) and ev.get("text"):
                text = ev["text"]
            # Usage may appear on turn.completed / thread events.
            u = ev.get("usage") or item.get("usage") or {}
            if isinstance(u, dict) and u:
                usage.input_tokens = int(u.get("input_tokens") or usage.input_tokens)
                usage.output_tokens = int(u.get("output_tokens") or usage.output_tokens)
                usage.cached_input_tokens = int(
                    u.get("cached_input_tokens")
                    or u.get("cache_read_input_tokens")
                    or usage.cached_input_tokens
                )
            if item.get("type") == "error" or typ == "error" or typ == "turn.failed":
                msg = str(item.get("message") or ev.get("message") or "")
                if any(w in msg.lower() for w in ("quota", "rate limit", "usage limit", "429")):
                    quota = True
        if any(w in (stderr or "").lower() for w in ("quota", "rate limit", "usage limit", "429")):
            quota = True
        usage.uncached_input_tokens = max(0, usage.input_tokens - usage.cached_input_tokens)
        return (text or stdout.strip(), usage, quota)


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

    def _argv(self, binpath: str, model_id: str, prompt: str) -> tuple[list[str], str | None]:
        argv = [binpath, "--print", "--output-format", "json"]
        if model_id and model_id != "default":
            argv += ["--model", model_id]
        argv += [prompt]
        return argv, None

    def _parse_full(self, stdout: str, stderr: str, code: int):
        from ..models import TokenUsage

        usage = TokenUsage()
        quota = "quota" in (stderr or "").lower() or "usage limit" in (stderr or "").lower()
        try:
            obj = json.loads(stdout)
        except json.JSONDecodeError:
            return (stdout.strip(), usage, quota)
        if not isinstance(obj, dict):
            return (stdout.strip(), usage, quota)
        if obj.get("is_error") or obj.get("subtype") == "error_max_turns":
            api = str(obj.get("api_error_status") or "")
            if "429" in api or "quota" in api.lower() or "limit" in api.lower():
                quota = True
        text = str(obj.get("result") or obj.get("content") or "")
        u = obj.get("usage") or {}
        if isinstance(u, dict):
            usage.input_tokens = int(u.get("input_tokens") or 0)
            usage.output_tokens = int(u.get("output_tokens") or 0)
            usage.cached_input_tokens = int(u.get("cache_read_input_tokens") or 0)
            usage.cache_creation_tokens = int(u.get("cache_creation_input_tokens") or 0)
            usage.uncached_input_tokens = usage.input_tokens
        # Claude reports total cost + the actual routed model(s).
        cost = obj.get("total_cost_usd")
        if cost is not None:
            usage.provider_reported_cost = float(cost)
        model_usage = obj.get("modelUsage") or {}
        if isinstance(model_usage, dict) and model_usage:
            # Pick the model with the most output tokens as the principal actual model.
            principal = max(
                model_usage.items(), key=lambda kv: (kv[1] or {}).get("outputTokens", 0)
            )[0]
            usage.actual_model = principal
        return (text, usage, quota)
