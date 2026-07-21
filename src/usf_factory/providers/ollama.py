"""Ollama (local) adapter.

Local inference over the Ollama HTTP API. Local providers are ``local_only`` for
egress and free, so ``invoke`` is not gated by the billable flag. Discovery uses
the native ``/api/tags`` endpoint.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

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


class OllamaAdapter:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        allow_billable: bool = False,
        timeout_s: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.allow_billable = allow_billable  # unused; local is free
        self._timeout = timeout_s
        self._transport = transport

    def _base(self) -> str:
        return (self.config.base_url or "http://localhost:11434").rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, transport=self._transport)

    async def discover_models(self) -> list[DiscoveredModel]:
        url = f"{self._base()}/api/tags"
        try:
            async with self._client() as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            raise AdapterError(f"ollama discovery failed: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise AdapterError(f"ollama discovery HTTP {resp.status_code}")
        body = resp.json()
        out: list[DiscoveredModel] = []
        for m in body.get("models", []) if isinstance(body, dict) else []:
            name = str(m.get("name") or m.get("model") or "").strip()
            if not name:
                continue
            details = m.get("details") or {}
            out.append(
                DiscoveredModel(
                    provider_id=self.config.provider_id,
                    requested_model_id=name,
                    display_name=name,
                    modalities=[Modality.TEXT],
                    free=True,
                    raw={"size": m.get("size"), "family": details.get("family")},
                )
            )
        return out

    async def probe_auth(self) -> ProviderHealth:
        url = f"{self._base()}/api/tags"
        start = time.perf_counter()
        try:
            async with self._client() as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.UNAVAILABLE,
                detail=type(exc).__name__,
            )
        latency = (time.perf_counter() - start) * 1000
        status = HealthStatus.HEALTHY if resp.status_code < 400 else HealthStatus.DEGRADED
        return ProviderHealth(
            provider_id=self.config.provider_id,
            status=status,
            detail=f"HTTP {resp.status_code}",
            latency_ms=latency,
        )

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        start = time.perf_counter()
        resp = await self._chat(model_id, probe.prompt)
        latency = (time.perf_counter() - start) * 1000
        return ProbeResult(
            kind=probe.kind,
            version=probe.version,
            passed=bool(resp.output_text),
            score=1.0 if resp.output_text else 0.0,
            actual_model_id=resp.actual_model,
            latency_ms=latency,
        )

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        model_id = request.agent_profile_id.split(":", 1)[-1]
        return await self._chat(model_id, request.instructions)

    async def _chat(self, model_id: str, prompt: str) -> AgentResponse:
        url = f"{self._base()}/api/chat"
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0},
        }
        try:
            async with self._client() as client:
                resp = await client.post(url, json=payload)
        except httpx.HTTPError as exc:
            raise AdapterError(f"ollama invoke failed: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise AdapterError(f"ollama invoke HTTP {resp.status_code}")
        body = resp.json()
        text = ""
        if isinstance(body, dict):
            text = (body.get("message") or {}).get("content", "") or ""
        return AgentResponse(
            agent_profile_id=f"{self.config.provider_id}:{model_id}",
            actual_provider=self.config.provider_id,
            actual_model=model_id,
            output_text=text,
        )
