"""Generic OpenAI-compatible provider adapter.

Covers openai-api, openrouter, groq, mistral, gemini (OpenAI endpoint),
sambanova, github-models, huggingface, fireworks, together, deepseek, cerebras,
arcee, xai-grok, anthropic-api. Provider-specific behavior is expressed through
config (base_url, models_endpoint) and small hooks, not forks.

Discovery and auth probes are metadata-only (not billable). ``probe_model`` and
``invoke`` are billable and refuse to run unless billing is explicitly allowed.
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


class OpenAICompatibleAdapter:
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
        self._transport = transport  # for tests (respx/mocks)
        self._loop_model: str | None = None  # model id used by chat_with_tools

    def with_loop_model(self, model_id: str) -> OpenAICompatibleAdapter:
        self._loop_model = model_id
        return self

    # ---- helpers -------------------------------------------------------- #

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self.config.provider_id == "openrouter":
            headers["HTTP-Referer"] = "https://usf-factory.local"
            headers["X-Title"] = "usf-factory"
        return headers

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout, transport=self._transport)

    def _url(self, endpoint: str | None) -> str:
        base = (self.config.base_url or "").rstrip("/")
        ep = endpoint or "/models"
        if ep.startswith("http://") or ep.startswith("https://"):
            return ep
        return f"{base}{ep}"

    # ---- discovery ------------------------------------------------------ #

    async def discover_models(self) -> list[DiscoveredModel]:
        url = self._url(self.config.models_endpoint)
        try:
            async with self._client() as client:
                resp = await client.get(url, headers=self._headers())
        except httpx.HTTPError as exc:
            raise AdapterError(
                f"{self.config.provider_id} discovery failed: {type(exc).__name__}"
            ) from exc
        if resp.status_code >= 400:
            raise AdapterError(f"{self.config.provider_id} discovery HTTP {resp.status_code}")
        return self._parse_models(resp.json())

    def _parse_models(self, body: Any) -> list[DiscoveredModel]:
        # OpenAI shape: {"data": [{"id": ...}, ...]}; some return a bare list.
        items: list[dict[str, Any]]
        if isinstance(body, dict) and isinstance(body.get("data"), list):
            items = body["data"]
        elif isinstance(body, list):
            items = body
        elif isinstance(body, dict) and isinstance(body.get("models"), list):
            items = body["models"]
        else:
            items = []
        out: list[DiscoveredModel] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            model_id = str(it.get("id") or it.get("name") or it.get("model") or "").strip()
            if not model_id:
                continue
            if self.config.provider_id == "openrouter":
                out.append(self._normalize_openrouter(model_id, it))
            else:
                out.append(
                    DiscoveredModel(
                        provider_id=self.config.provider_id,
                        requested_model_id=model_id,
                        display_name=str(it.get("name")) if it.get("name") else None,
                        context_tokens=_as_int(
                            it.get("context_length") or it.get("context_window")
                        ),
                        output_tokens=_as_int(
                            it.get("max_output_tokens") or it.get("max_completion_tokens")
                        ),
                        modalities=[Modality.TEXT],
                        claims_tools=_as_bool(it.get("supports_tools")),
                        claims_structured_output=_as_bool(it.get("supports_structured_output")),
                        prompt_cost_per_mtok=_pricing(it, "prompt"),
                        output_cost_per_mtok=_pricing(it, "completion"),
                        raw=_compact_raw(it),
                    )
                )
        return out

    def _normalize_openrouter(self, model_id: str, it: dict[str, Any]) -> DiscoveredModel:
        """Provider-specific normalizer capturing OpenRouter's rich catalogue:
        supported_parameters (tools/reasoning/structured_outputs), context length,
        max completion tokens, and pricing."""
        params = it.get("supported_parameters") or []
        params = [str(p) for p in params] if isinstance(params, list) else []
        top = it.get("top_provider") or {}
        pricing = it.get("pricing") or {}
        free = model_id.endswith(":free") or (str(pricing.get("prompt", "1")) in ("0", "0.0"))
        return DiscoveredModel(
            provider_id="openrouter",
            requested_model_id=model_id,
            display_name=str(it.get("name")) if it.get("name") else None,
            context_tokens=_as_int(it.get("context_length")),
            output_tokens=_as_int(top.get("max_completion_tokens")),
            modalities=[Modality.TEXT],
            claims_tools="tools" in params,
            claims_structured_output="structured_outputs" in params or "response_format" in params,
            claims_reasoning="reasoning" in params or "include_reasoning" in params,
            prompt_cost_per_mtok=_openrouter_price(pricing, "prompt"),
            output_cost_per_mtok=_openrouter_price(pricing, "completion"),
            free=free,
            supported_parameters=params,
            raw=_compact_raw(it),
        )

    # ---- auth probe ----------------------------------------------------- #

    async def probe_auth(self) -> ProviderHealth:
        url = self._url(self.config.models_endpoint)
        start = time.perf_counter()
        try:
            async with self._client() as client:
                resp = await client.get(url, headers=self._headers())
        except httpx.HTTPError as exc:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status=HealthStatus.UNAVAILABLE,
                detail=type(exc).__name__,
            )
        latency = (time.perf_counter() - start) * 1000
        if resp.status_code in (401, 403):
            status = HealthStatus.UNAUTHENTICATED
        elif resp.status_code == 429:
            status = HealthStatus.DEGRADED
        elif resp.status_code >= 500:
            status = HealthStatus.UNAVAILABLE
        elif resp.status_code >= 400:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        return ProviderHealth(
            provider_id=self.config.provider_id,
            status=status,
            detail=f"HTTP {resp.status_code}",
            latency_ms=latency,
        )

    # ---- billable operations -------------------------------------------- #

    def _ensure_billable(self) -> None:
        if not self.allow_billable:
            raise AdapterError(
                f"billable inference disabled for {self.config.provider_id}; "
                f"pass --allow-billable and a budget to enable"
            )

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        self._ensure_billable()
        start = time.perf_counter()
        resp = await self._chat(model_id, probe.prompt)
        latency = (time.perf_counter() - start) * 1000
        return ProbeResult(
            kind=probe.kind,
            version=probe.version,
            passed=bool(resp.output_text),
            score=1.0 if resp.output_text else 0.0,
            detail="raw probe response captured",
            actual_model_id=resp.actual_model,
            latency_ms=latency,
        )

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        self._ensure_billable()
        if request.provider_id and request.provider_id != self.config.provider_id:
            raise AdapterError(
                f"request provider {request.provider_id!r} does not match adapter "
                f"{self.config.provider_id!r}"
            )
        model_id = request.model_id_for(request.agent_profile_id.split(":", 1)[-1])
        if not model_id or model_id.startswith("agent-"):
            raise AdapterError(
                "AgentRequest.requested_model_id is required; refusing to derive a "
                "model id from an opaque agent_profile_id"
            )
        return await self._chat(model_id, request.instructions)

    async def chat_with_tools(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """One tool-enabled chat turn (for the agent tool-loop). Billable; gated.

        Returns ``{"content": str, "tool_calls": [{"id","name","arguments"}]}``.
        """
        self._ensure_billable()
        url = self._url("/chat/completions")
        payload = {
            "model": self._loop_model or "gpt-4o-mini",
            "messages": _to_openai_messages(messages),
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0,
        }
        try:
            async with self._client() as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
        except httpx.HTTPError as exc:
            raise AdapterError(
                f"{self.config.provider_id} chat failed: {type(exc).__name__}"
            ) from exc
        if resp.status_code >= 400:
            raise AdapterError(f"{self.config.provider_id} chat HTTP {resp.status_code}")
        msg = ((resp.json().get("choices") or [{}])[0]).get("message", {})
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            import json as _json

            try:
                args = _json.loads(fn.get("arguments") or "{}")
            except _json.JSONDecodeError:
                args = {}
            calls.append({"id": tc.get("id", ""), "name": fn.get("name", ""), "arguments": args})
        return {"content": msg.get("content") or "", "tool_calls": calls}

    async def _chat(self, model_id: str, prompt: str) -> AgentResponse:
        url = self._url("/chat/completions")
        payload = {
            "model": model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        try:
            async with self._client() as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
        except httpx.HTTPError as exc:
            raise AdapterError(
                f"{self.config.provider_id} invoke failed: {type(exc).__name__}"
            ) from exc
        if resp.status_code >= 400:
            raise AdapterError(f"{self.config.provider_id} invoke HTTP {resp.status_code}")
        body = resp.json()
        text = ""
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            text = ""
        usage = body.get("usage") or {}
        return AgentResponse(
            agent_profile_id=f"{self.config.provider_id}:{model_id}",
            actual_provider=self.config.provider_id,
            actual_model=str(body.get("model") or model_id),  # routed actual model
            output_text=text,
            structured={},
            tokens_in=_as_int(usage.get("prompt_tokens")),
            tokens_out=_as_int(usage.get("completion_tokens")),
        )


def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize the tool-loop message list into OpenAI chat format.

    Tool results in our loop carry dict content; OpenAI expects string content on
    ``role=tool`` messages, so we JSON-encode them.
    """
    import json as _json

    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") == "tool":
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": m.get("tool_call_id", ""),
                    "content": _json.dumps(m.get("content", {})),
                }
            )
        else:
            out.append({k: v for k, v in m.items() if k in ("role", "content", "tool_calls")})
    return out


def _openrouter_price(pricing: dict[str, Any], kind: str) -> float | None:
    """OpenRouter prices are per-token strings; convert to per-million-tokens."""
    val = pricing.get(kind)
    try:
        return float(val) * 1_000_000 if val is not None else None
    except (TypeError, ValueError):
        return None


def _as_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    return None


def _pricing(it: dict[str, Any], kind: str) -> float | None:
    pricing = it.get("pricing")
    if isinstance(pricing, dict):
        val = pricing.get(kind) or pricing.get(f"{kind}_cost")
        try:
            return float(val) * 1_000_000 if val is not None else None
        except (TypeError, ValueError):
            return None
    return None


def _compact_raw(it: dict[str, Any]) -> dict[str, Any]:
    """Keep only small, non-sensitive descriptive fields from the raw record."""
    keep = ("id", "name", "created", "owned_by", "context_length", "pricing")
    return {k: it[k] for k in keep if k in it}
