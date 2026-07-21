"""Provider registry: enablement, adapter construction, discovery, health.

Enablement gates: a provider is *enabled* only when it is configured
(``default_enabled``), not excluded, and its credential is present. github-models
additionally requires a Models-permission probe (kept disabled by config until
proven). xai-grok / anthropic-api stay disabled without their keys.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from ..clock import utc_now_iso
from ..context import RuntimeContext
from ..model_registry import normalize_model
from ..models import ProviderCatalogueSnapshot, ProviderConfig, ProviderHealth
from .base import AdapterError, ProviderAdapter
from .cli_adapters import ClaudeCliAdapter, CodexCliAdapter
from .ollama import OllamaAdapter
from .openai_compatible import OpenAICompatibleAdapter


@dataclass
class EnablementStatus:
    provider_id: str
    enabled: bool
    reason: str
    credential_present: bool
    requires_probe: bool = False


@dataclass
class DiscoveryOutcome:
    provider_id: str
    ok: bool
    model_count: int = 0
    catalog_id: str | None = None
    error: str | None = None
    health: ProviderHealth | None = None


@dataclass
class ProviderRegistry:
    ctx: RuntimeContext
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    excluded: list[str] = field(default_factory=list)
    _transport: httpx.AsyncBaseTransport | None = None  # test injection
    # Runtime override for the adapter billable gate. None => use the committed
    # config.safety.allow_billable. Explicit probing/qualification with
    # --allow-paid/--allow-subscription passes True WITHOUT mutating committed
    # policy; the local (free) path never needs it.
    allow_billable_override: bool | None = None

    # ---- enablement ----------------------------------------------------- #

    def enablement(self, provider_id: str) -> EnablementStatus:
        cfg = self.providers[provider_id]
        cred_present = self.ctx.credential_present(cfg.credential_reference)

        if not cfg.default_enabled:
            if provider_id == "github-models":
                return EnablementStatus(
                    provider_id,
                    False,
                    "requires Models-permission probe before admission",
                    cred_present,
                    requires_probe=True,
                )
            reason = "disabled in config"
            if not cred_present:
                reason = f"disabled in config; credential {cfg.credential_reference} absent"
            return EnablementStatus(provider_id, False, reason, cred_present)

        if cfg.auth_mode.value == "api_token" and not cred_present:
            return EnablementStatus(
                provider_id,
                False,
                f"missing credential {cfg.credential_reference}",
                cred_present,
            )
        return EnablementStatus(provider_id, True, "enabled", cred_present)

    def all_enablement(self) -> dict[str, EnablementStatus]:
        return {pid: self.enablement(pid) for pid in sorted(self.providers)}

    def enabled_ids(self) -> list[str]:
        return [pid for pid, st in self.all_enablement().items() if st.enabled]

    # ---- adapter construction ------------------------------------------- #

    def adapter(self, provider_id: str) -> ProviderAdapter:
        cfg = self.providers[provider_id]
        allow_billable = (
            self.allow_billable_override
            if self.allow_billable_override is not None
            else self.ctx.config.safety.allow_billable
        )
        kind = cfg.adapter
        if kind == "openai_compatible":
            token = (
                self.ctx.credential_value(cfg.credential_reference)
                if cfg.credential_reference and cfg.credential_reference.startswith("env:")
                else None
            )
            return OpenAICompatibleAdapter(
                cfg, token, allow_billable=allow_billable, transport=self._transport
            )
        if kind == "anthropic":
            from .anthropic import AnthropicAdapter

            token = (
                self.ctx.credential_value(cfg.credential_reference)
                if cfg.credential_reference and cfg.credential_reference.startswith("env:")
                else None
            )
            return AnthropicAdapter(
                cfg, token, allow_billable=allow_billable, transport=self._transport
            )
        if kind == "ollama":
            return OllamaAdapter(cfg, allow_billable=allow_billable, transport=self._transport)
        if kind == "codex_cli":
            return CodexCliAdapter(cfg, allow_billable=allow_billable)
        if kind == "claude_cli":
            return ClaudeCliAdapter(cfg, allow_billable=allow_billable)
        raise AdapterError(f"unknown adapter kind: {kind}")

    # ---- discovery + health --------------------------------------------- #

    async def discover_one(self, provider_id: str) -> DiscoveryOutcome:
        cfg = self.providers[provider_id]
        adapter = self.adapter(provider_id)
        # Always record a health observation.
        health = await adapter.probe_auth()
        self.ctx.store.append(
            "provider_health_events",
            health.model_dump(mode="json"),
            extra={"provider_id": provider_id, "status": health.status.value},
        )
        try:
            models = await adapter.discover_models()
        except AdapterError as exc:
            return DiscoveryOutcome(provider_id, False, error=str(exc), health=health)

        now = utc_now_iso()
        cat = ProviderCatalogueSnapshot(
            provider_id=provider_id,
            models=models,
            discovered_at=now,
            source=cfg.adapter,
        )
        cat_id = cat.catalog_id
        cat_digest = cat.digest()
        self.ctx.store.put(
            "provider_catalogues",
            cat_id,
            cat.content_dict(),
            digest=cat_digest,
            extra={"provider_id": provider_id, "expires_at": ""},
        )
        # Normalize and persist model records.
        for dm in models:
            record = normalize_model(
                dm, cfg, catalogue_id=cat_id, catalogue_digest=cat_digest, discovered_at=now
            )
            self.ctx.store.put(
                "models",
                record.model_key,
                record.content_dict(),
                digest=record.digest(),
                extra={"provider_id": provider_id},
            )
        return DiscoveryOutcome(
            provider_id, True, model_count=len(models), catalog_id=cat_id, health=health
        )

    async def discover_all(
        self, provider_ids: list[str] | None = None
    ) -> dict[str, DiscoveryOutcome]:
        ids = provider_ids or self.enabled_ids()
        results = await asyncio.gather(
            *(self.discover_one(pid) for pid in ids), return_exceptions=True
        )
        out: dict[str, DiscoveryOutcome] = {}
        for pid, res in zip(ids, results, strict=True):
            if isinstance(res, DiscoveryOutcome):
                out[pid] = res
            else:
                out[pid] = DiscoveryOutcome(pid, False, error=f"{type(res).__name__}: {res}")
        return out

    async def health_all(self, provider_ids: list[str] | None = None) -> dict[str, ProviderHealth]:
        ids = provider_ids or list(self.providers)

        async def probe(pid: str) -> ProviderHealth:
            try:
                return await self.adapter(pid).probe_auth()
            except AdapterError as exc:
                from ..enums import HealthStatus

                return ProviderHealth(
                    provider_id=pid, status=HealthStatus.UNAVAILABLE, detail=str(exc)
                )

        results = await asyncio.gather(*(probe(pid) for pid in ids))
        return dict(zip(ids, results, strict=True))


def build_registry(
    ctx: RuntimeContext,
    transport: httpx.AsyncBaseTransport | None = None,
    *,
    allow_billable: bool | None = None,
) -> ProviderRegistry:
    pconf = ctx.config.providers
    excluded = list(pconf.exclude)
    # Codebuff (and any excluded id) is never even registered.
    providers = {p.provider_id: p for p in pconf.providers if p.provider_id not in excluded}
    return ProviderRegistry(
        ctx=ctx,
        providers=providers,
        excluded=excluded,
        _transport=transport,
        allow_billable_override=allow_billable,
    )
