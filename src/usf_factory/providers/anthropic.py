"""Native Anthropic adapter (review P1-16).

Anthropic's API is NOT OpenAI-compatible: it uses ``/v1/messages``, an
``x-api-key`` header, and an ``anthropic-version`` header, with its own message
and tool shapes. This adapter models that directly. Disabled unless
``ANTHROPIC_API_KEY`` is supplied; invocation is billable and gated.
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

_ANTHROPIC_VERSION = "2023-06-01"

# Curated fallback catalogue (Anthropic's /v1/models may require auth).
_KNOWN = (
    ("claude-opus-4-8", 200000, 64000),
    ("claude-sonnet-5", 200000, 64000),
    ("claude-haiku-4-5-20251001", 200000, 32000),
)


class AnthropicAdapter:
    def __init__(
        self,
        config: ProviderConfig,
        token: str | None,
        *,
        allow_billable: bool = False,
        timeout_s: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self._token = token
        self.allow_billable = allow_billable
        self._timeout = timeout_s
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json", "anthropic-version": _ANTHROPIC_VERSION}
        if self._token:
            h["x-api-key"] = self._token
        return h

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, transport=self._transport)

    def _url(self, path: str) -> str:
        base = (self.config.base_url or "https://api.anthropic.com/v1").rstrip("/")
        return f"{base}{path}"

    async def discover_models(self) -> list[DiscoveredModel]:
        try:
            async with self._client() as client:
                resp = await client.get(self._url("/models"), headers=self._headers())
            if resp.status_code < 400:
                data = resp.json().get("data", [])
                out = []
                for it in data:
                    mid = str(it.get("id") or "").strip()
                    if mid:
                        out.append(
                            DiscoveredModel(
                                provider_id=self.config.provider_id,
                                requested_model_id=mid,
                                display_name=str(it.get("display_name") or mid),
                                modalities=[Modality.TEXT],
                                claims_tools=True,
                            )
                        )
                if out:
                    return out
        except httpx.HTTPError:
            pass
        # Fallback to the curated catalogue.
        return [
            DiscoveredModel(
                provider_id=self.config.provider_id,
                requested_model_id=mid,
                display_name=mid,
                context_tokens=ctx,
                output_tokens=out,
                modalities=[Modality.TEXT],
                claims_tools=True,
                claims_structured_output=True,
                claims_reasoning=True,
            )
            for mid, ctx, out in _KNOWN
        ]

    async def probe_auth(self) -> ProviderHealth:
        start = time.perf_counter()
        try:
            async with self._client() as client:
                resp = await client.get(self._url("/models"), headers=self._headers())
        except httpx.HTTPError as exc:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.UNAVAILABLE,
                detail=type(exc).__name__,
            )
        latency = (time.perf_counter() - start) * 1000
        status = {
            401: HealthStatus.UNAUTHENTICATED,
            403: HealthStatus.UNAUTHENTICATED,
            429: HealthStatus.DEGRADED,
        }.get(
            resp.status_code,
            HealthStatus.HEALTHY if resp.status_code < 400 else HealthStatus.DEGRADED,
        )
        return ProviderHealth(
            provider_id=self.config.provider_id,
            status=status,
            detail=f"HTTP {resp.status_code}",
            latency_ms=latency,
        )

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        if not self.allow_billable:
            raise AdapterError(f"billable inference disabled for {self.config.provider_id}")
        resp = await self._messages(model_id, probe.prompt)
        return ProbeResult(
            kind=probe.kind,
            version=probe.version,
            passed=bool(resp.output_text),
            score=1.0 if resp.output_text else 0.0,
            actual_model_id=resp.actual_model,
        )

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        if not self.allow_billable:
            raise AdapterError(f"billable inference disabled for {self.config.provider_id}")
        model_id = request.model_id_for("claude-sonnet-5")
        if model_id.startswith("agent-"):
            raise AdapterError("AgentRequest.requested_model_id is required")
        return await self._messages(model_id, request.instructions)

    async def _messages(self, model_id: str, prompt: str) -> AgentResponse:
        payload: dict[str, Any] = {
            "model": model_id,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            async with self._client() as client:
                resp = await client.post(
                    self._url("/messages"), headers=self._headers(), json=payload
                )
        except httpx.HTTPError as exc:
            raise AdapterError(f"anthropic invoke failed: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise AdapterError(f"anthropic invoke HTTP {resp.status_code}")
        body = resp.json()
        text = ""
        for block in body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                text += block.get("text", "")
        usage = body.get("usage") or {}
        return AgentResponse(
            agent_profile_id=f"{self.config.provider_id}:{model_id}",
            actual_provider=self.config.provider_id,
            actual_model=str(body.get("model") or model_id),
            output_text=text,
            tokens_in=usage.get("input_tokens"),
            tokens_out=usage.get("output_tokens"),
        )
