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
        timeout_s: float = 300.0,  # local inference (esp. large quantized models) is slow
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.allow_billable = allow_billable  # unused; local is free
        self._timeout = timeout_s
        self._transport = transport
        self._loop_model: str | None = None

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

    def with_loop_model(self, model_id: str) -> OllamaAdapter:
        self._loop_model = model_id
        return self

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        """Run ONE probe against the live local model and grade it deterministically
        with the canonical graders. Forced/prohibited tool probes pass the probe's
        tool spec so a genuine tool call is exercised."""
        from ..probes import grade_probe

        start = time.perf_counter()
        tools = None
        if probe.permitted_tools or probe.kind.value in ("forced_tool_call",):
            tools = [
                {"type": "function", "function": {"name": t, "parameters": {"type": "object"}}}
                for t in (probe.permitted_tools or ["lookup"])
            ]
        raw, tool_calls, _usage = await self._raw_chat(
            model_id, [{"role": "user", "content": probe.prompt}], tools=tools
        )
        latency = (time.perf_counter() - start) * 1000
        result = grade_probe(probe, raw, tool_calls=tool_calls, actual_model_id=model_id)
        return result.model_copy(update={"latency_ms": latency})

    async def chat_with_tools(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """One tool-enabled chat turn for the brokered agent loop. Local => free."""
        model = self._loop_model
        if not model:
            raise AdapterError("ollama chat_with_tools requires with_loop_model() first")
        content, tool_calls, usage = await self._raw_chat(model, messages, tools=tools)
        return {
            "content": content,
            "tool_calls": tool_calls,
            "actual_model": model,
            "usage": usage,
        }

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        model_id = request.model_id_for(request.agent_profile_id.split(":", 1)[-1])
        if not model_id or model_id.startswith("agent-"):
            raise AdapterError(
                "AgentRequest.requested_model_id is required; refusing to derive a "
                "model id from an opaque agent_profile_id"
            )
        content, _calls, usage = await self._raw_chat(
            model_id, [{"role": "user", "content": request.instructions}]
        )
        return AgentResponse(
            agent_profile_id=f"{self.config.provider_id}:{model_id}",
            actual_provider=self.config.provider_id,
            actual_model=model_id,
            output_text=content,
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
        )

    async def _raw_chat(
        self,
        model_id: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> tuple[str, list[dict[str, Any]], dict[str, int]]:
        """One /api/chat turn. Returns (content, tool_calls, token usage)."""
        url = f"{self._base()}/api/chat"
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": _to_ollama_messages(messages),
            "stream": False,
            "options": {"temperature": 0},
        }
        if tools:
            payload["tools"] = tools
        try:
            async with self._client() as client:
                resp = await client.post(url, json=payload)
        except httpx.HTTPError as exc:
            raise AdapterError(f"ollama chat failed: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise AdapterError(f"ollama chat HTTP {resp.status_code}")
        body = resp.json() if resp.content else {}
        msg = body.get("message") or {} if isinstance(body, dict) else {}
        content = msg.get("content", "") or ""
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments")
            if isinstance(args, str):
                import json as _json

                try:
                    args = _json.loads(args or "{}")
                except _json.JSONDecodeError:
                    args = {}
            calls.append(
                {"id": tc.get("id", ""), "name": fn.get("name", ""), "arguments": args or {}}
            )
        usage = {
            "prompt_tokens": int(body.get("prompt_eval_count") or 0),
            "completion_tokens": int(body.get("eval_count") or 0),
        }
        return content, calls, usage


def _to_ollama_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map the loop's generic message shape to Ollama's chat format."""
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role == "tool":
            import json as _json

            payload = content if isinstance(content, str) else _json.dumps(content, sort_keys=True)
            out.append({"role": "tool", "content": payload})
        elif role == "assistant" and m.get("tool_calls"):
            out.append(
                {
                    "role": "assistant",
                    "content": content or "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": c.get("name", ""),
                                "arguments": c.get("arguments", {}),
                            }
                        }
                        for c in m["tool_calls"]
                    ],
                }
            )
        else:
            out.append(
                {"role": role, "content": content if isinstance(content, str) else str(content)}
            )
    return out
