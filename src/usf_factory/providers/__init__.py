"""Provider adapters and registry.

A provider adapter knows how to discover models, probe auth, probe a model's
mechanical capabilities, and invoke it. Adapters are the ONLY place that touches
provider credentials, and they never log a value.
"""

from __future__ import annotations

from .base import AdapterError, ProviderAdapter
from .registry import ProviderRegistry, build_registry

__all__ = ["AdapterError", "ProviderAdapter", "ProviderRegistry", "build_registry"]
