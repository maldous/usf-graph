"""USF Adaptive Semantic Factory.

A deterministic, model-agnostic orchestration engine that advances USF semantic
work. The deterministic control plane owns the loop; AI providers are
replaceable, qualified workers.

Safe-by-default: no /usf mutation, no Stardog mutation, no billable inference,
no source egress, no publication — unless explicitly and separately enabled.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.4.0"
