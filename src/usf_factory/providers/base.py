"""Provider adapter protocol and shared helpers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import (
    AgentRequest,
    AgentResponse,
    DiscoveredModel,
    ProbeResult,
    ProbeSpec,
    ProviderConfig,
    ProviderHealth,
)


class AdapterError(Exception):
    """An adapter-level failure (network, protocol, auth)."""


@runtime_checkable
class ProviderAdapter(Protocol):
    """The uniform provider interface (DESIGN §6)."""

    config: ProviderConfig

    async def discover_models(self) -> list[DiscoveredModel]:
        """List available models (a dated claim). Metadata-only; not billable."""
        ...

    async def probe_auth(self) -> ProviderHealth:
        """Cheap liveness + auth probe. Metadata-only; not billable."""
        ...

    async def probe_model(self, model_id: str, probe: ProbeSpec) -> ProbeResult:
        """Run one mechanical probe against a model. May be billable — gated."""
        ...

    async def invoke(self, request: AgentRequest) -> AgentResponse:
        """Invoke a model for real work. Billable — gated by the caller."""
        ...
