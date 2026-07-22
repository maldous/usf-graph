"""Unified WorkforcePolicy (dynamic workforce spec §2).

ONE policy object drives discovery, provider evaluation, probing, qualification,
admission, workforce construction, packet routing, fallback, reviewer/integrator
selection and autonomous realisation. It carries only *axes* — providers,
models, families, adapters, actual routed models, and inference classes — never a
role→provider preference. Roles stay abstract execution requirements.

Three layers compose into one effective policy:

    committed defaults  <  operator policy file  <  run-specific CLI overrides

Precedence (spec §2):

    run exclusion > operator exclusion > committed exclusion
      > inclusion / preference > automatic selection

An exclusion is the UNION across layers and can never be overridden by an
inclusion or an automatic fallback. Inclusions (``only_*``) and scalar limits
take the highest layer that sets them (run > operator > committed). Safety
requirements (``require_*``) take the STRICTEST value across layers — a lower
layer can never relax a requirement a higher (or committed) layer asserts.

The effective policy's digest is recorded in every workforce snapshot, routing
decision, qualification record, packet/review/delivery receipt.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from .enums import InferenceMode
from .errors import ConfigError
from .model_registry import family_matches
from .models import FactoryModel

# Layer names in ascending precedence order.
LAYER_COMMITTED = "committed"
LAYER_OPERATOR = "operator"
LAYER_RUN = "run"
_LAYER_ORDER = (LAYER_COMMITTED, LAYER_OPERATOR, LAYER_RUN)


class WorkforcePolicyLayer(FactoryModel):
    """One raw policy layer. Unset tri-state fields (``None``) inherit."""

    # Exclusions (union across layers; an exclusion always wins).
    exclude_providers: list[str] = Field(default_factory=list)
    exclude_models: list[str] = Field(default_factory=list)  # "provider/model" or bare model id
    exclude_provider_models: list[str] = Field(default_factory=list)  # explicit "provider/model"
    exclude_families: list[str] = Field(default_factory=list)
    exclude_adapters: list[str] = Field(default_factory=list)
    exclude_actual_models: list[str] = Field(default_factory=list)

    # Inclusions / allowlists (highest layer that sets a non-empty list wins).
    only_providers: list[str] = Field(default_factory=list)
    only_models: list[str] = Field(default_factory=list)
    only_families: list[str] = Field(default_factory=list)
    only_inference_modes: list[InferenceMode] = Field(default_factory=list)

    # Inference-class gates (tri-state: None inherits).
    allow_local: bool | None = None
    allow_free: bool | None = None
    allow_subscription: bool | None = None
    allow_paid: bool | None = None

    # Scalar limits (None inherits / no limit).
    max_paid_cost_usd: float | None = None
    max_subscription_value_usd: float | None = None
    max_concurrent_by_provider: int | None = None
    max_requests_per_provider: int | None = None
    max_models_assessed: int | None = None

    # Safety requirements (tri-state; strictest wins).
    require_verified_actual_model_for_mutation: bool | None = None
    require_source_containment_for_private_source: bool | None = None
    require_provider_diverse_review: bool | None = None
    require_family_diverse_review: bool | None = None


def committed_defaults() -> WorkforcePolicyLayer:
    """The committed baseline. Deliberately provider-neutral: it names NO
    provider/model/family and excludes nothing by identity (spec §11 — historical
    default exclusions such as ollama/llama are removed). Non-paid inference is
    allowed; paid is off until an operator enables it. Safety requirements are on."""
    return WorkforcePolicyLayer(
        allow_local=True,
        allow_free=True,
        allow_subscription=True,
        allow_paid=False,
        require_verified_actual_model_for_mutation=True,
        require_source_containment_for_private_source=True,
        require_provider_diverse_review=True,
        require_family_diverse_review=False,
    )


class ExclusionHit(FactoryModel):
    excluded: bool
    reason: str = ""
    source: str = ""  # committed | operator | run


class EffectiveWorkforcePolicy(FactoryModel):
    """The resolved policy: unioned exclusions (with source), resolved inclusions,
    inference gates, limits and requirements. Content-addressed via ``digest()``."""

    # value -> source layer (highest-precedence layer that excluded it)
    excluded_providers: dict[str, str] = Field(default_factory=dict)
    excluded_models: dict[str, str] = Field(default_factory=dict)
    excluded_provider_models: dict[str, str] = Field(default_factory=dict)
    excluded_families: dict[str, str] = Field(default_factory=dict)
    excluded_adapters: dict[str, str] = Field(default_factory=dict)
    excluded_actual_models: dict[str, str] = Field(default_factory=dict)

    only_providers: list[str] = Field(default_factory=list)
    only_models: list[str] = Field(default_factory=list)
    only_families: list[str] = Field(default_factory=list)
    only_inference_modes: list[InferenceMode] = Field(default_factory=list)

    allow_local: bool = True
    allow_free: bool = True
    allow_subscription: bool = True
    allow_paid: bool = False

    max_paid_cost_usd: float | None = None
    max_subscription_value_usd: float | None = None
    max_concurrent_by_provider: int | None = None
    max_requests_per_provider: int | None = None
    max_models_assessed: int | None = None

    require_verified_actual_model_for_mutation: bool = True
    require_source_containment_for_private_source: bool = True
    require_provider_diverse_review: bool = True
    require_family_diverse_review: bool = False

    def inference_allowed(self, mode: InferenceMode | str) -> bool:
        m = InferenceMode(mode)
        if self.only_inference_modes and m not in self.only_inference_modes:
            return False
        return {
            InferenceMode.LOCAL: self.allow_local,
            InferenceMode.FREE: self.allow_free,
            InferenceMode.SUBSCRIPTION: self.allow_subscription,
            InferenceMode.PAID: self.allow_paid,
        }[m]

    def candidate_exclusion(
        self,
        *,
        provider_id: str,
        model_id: str = "",
        family: str = "",
        adapter: str = "",
        actual_model: str = "",
        inference_mode: InferenceMode | str | None = None,
    ) -> ExclusionHit:
        """Fail-closed exclusion decision. Exclusions are checked first and always
        win; then allowlists; then inference gating. Returns the first hit with the
        source layer that produced it."""
        full = f"{provider_id}/{model_id}" if model_id else provider_id
        if provider_id in self.excluded_providers:
            return ExclusionHit(
                excluded=True,
                reason=f"provider '{provider_id}' excluded",
                source=self.excluded_providers[provider_id],
            )
        if adapter and adapter in self.excluded_adapters:
            return ExclusionHit(
                excluded=True,
                reason=f"adapter '{adapter}' excluded",
                source=self.excluded_adapters[adapter],
            )
        for key in (full, model_id):
            if key and key in self.excluded_provider_models:
                return ExclusionHit(
                    excluded=True,
                    reason=f"provider/model '{key}' excluded",
                    source=self.excluded_provider_models[key],
                )
            if key and key in self.excluded_models:
                return ExclusionHit(
                    excluded=True,
                    reason=f"model '{key}' excluded",
                    source=self.excluded_models[key],
                )
        if actual_model and actual_model in self.excluded_actual_models:
            return ExclusionHit(
                excluded=True,
                reason=f"actual routed model '{actual_model}' excluded",
                source=self.excluded_actual_models[actual_model],
            )
        for fam, src in self.excluded_families.items():
            if family_matches(provider_id, model_id, fam):
                return ExclusionHit(excluded=True, reason=f"family '{fam}' excluded", source=src)
        # Allowlists (inclusions) — lower precedence than exclusions.
        if self.only_providers and provider_id not in self.only_providers:
            return ExclusionHit(
                excluded=True,
                reason=f"provider '{provider_id}' not in only_providers",
                source="only_providers",
            )
        if (
            self.only_models
            and model_id
            and not (model_id in self.only_models or full in self.only_models)
        ):
            return ExclusionHit(
                excluded=True, reason=f"model '{full}' not in only_models", source="only_models"
            )
        if self.only_families and not any(
            family_matches(provider_id, model_id, fam) for fam in self.only_families
        ):
            return ExclusionHit(
                excluded=True, reason=f"'{full}' matches no only_families", source="only_families"
            )
        if inference_mode is not None and not self.inference_allowed(inference_mode):
            return ExclusionHit(
                excluded=True,
                reason=f"inference mode '{InferenceMode(inference_mode).value}' not allowed",
                source="inference_gate",
            )
        return ExclusionHit(excluded=False)

    def digest(self) -> str:
        return super().digest()


def _merge_exclusions(
    layers: list[tuple[str, list[str]]],
) -> dict[str, str]:
    """Union values across (layer_name, values); record the HIGHEST-precedence
    layer that lists each value as its source (run > operator > committed)."""
    out: dict[str, str] = {}
    for layer_name, values in layers:  # iterate in ascending precedence
        for v in values:
            out[v] = layer_name  # later (higher-precedence) layer overwrites source
    return out


def _first_set_list(layers: list[list[Any]]) -> list[Any]:
    """Highest-precedence non-empty list wins (layers in ascending precedence)."""
    chosen: list[Any] = []
    for values in layers:
        if values:
            chosen = list(values)
    return chosen


def _first_set_scalar(values: list[Any | None]) -> Any | None:
    """Highest-precedence explicitly-set (non-None) value wins."""
    chosen: Any | None = None
    for v in values:
        if v is not None:
            chosen = v
    return chosen


def _strictest_require(values: list[bool | None], default: bool) -> bool:
    """A requirement is asserted if ANY layer (or the default) asserts it; a lower
    layer can never relax it."""
    asserted = default
    for v in values:
        if v is True:
            asserted = True
    return asserted


def resolve_workforce_policy(
    committed: WorkforcePolicyLayer,
    operator: WorkforcePolicyLayer | None = None,
    run: WorkforcePolicyLayer | None = None,
) -> EffectiveWorkforcePolicy:
    """Compose the three layers into one effective, fail-closed policy."""
    operator = operator or WorkforcePolicyLayer()
    run = run or WorkforcePolicyLayer()
    ordered = [(LAYER_COMMITTED, committed), (LAYER_OPERATOR, operator), (LAYER_RUN, run)]

    def excl(attr: str) -> dict[str, str]:
        return _merge_exclusions([(name, getattr(layer, attr)) for name, layer in ordered])

    return EffectiveWorkforcePolicy(
        excluded_providers=excl("exclude_providers"),
        excluded_models=excl("exclude_models"),
        excluded_provider_models=excl("exclude_provider_models"),
        excluded_families=excl("exclude_families"),
        excluded_adapters=excl("exclude_adapters"),
        excluded_actual_models=excl("exclude_actual_models"),
        only_providers=_first_set_list([layer.only_providers for _, layer in ordered]),
        only_models=_first_set_list([layer.only_models for _, layer in ordered]),
        only_families=_first_set_list([layer.only_families for _, layer in ordered]),
        only_inference_modes=_first_set_list([layer.only_inference_modes for _, layer in ordered]),
        allow_local=_resolve_allow([layer.allow_local for _, layer in ordered], True),
        allow_free=_resolve_allow([layer.allow_free for _, layer in ordered], True),
        allow_subscription=_resolve_allow([layer.allow_subscription for _, layer in ordered], True),
        allow_paid=_resolve_allow([layer.allow_paid for _, layer in ordered], False),
        max_paid_cost_usd=_first_set_scalar([layer.max_paid_cost_usd for _, layer in ordered]),
        max_subscription_value_usd=_first_set_scalar(
            [layer.max_subscription_value_usd for _, layer in ordered]
        ),
        max_concurrent_by_provider=_first_set_scalar(
            [layer.max_concurrent_by_provider for _, layer in ordered]
        ),
        max_requests_per_provider=_first_set_scalar(
            [layer.max_requests_per_provider for _, layer in ordered]
        ),
        max_models_assessed=_first_set_scalar([layer.max_models_assessed for _, layer in ordered]),
        require_verified_actual_model_for_mutation=_strictest_require(
            [layer.require_verified_actual_model_for_mutation for _, layer in ordered], True
        ),
        require_source_containment_for_private_source=_strictest_require(
            [layer.require_source_containment_for_private_source for _, layer in ordered], True
        ),
        require_provider_diverse_review=_strictest_require(
            [layer.require_provider_diverse_review for _, layer in ordered], True
        ),
        require_family_diverse_review=_strictest_require(
            [layer.require_family_diverse_review for _, layer in ordered], False
        ),
    )


def _resolve_allow(values: list[bool | None], default: bool) -> bool:
    chosen = _first_set_scalar(values)
    return default if chosen is None else bool(chosen)


def load_policy_layer(path: Path | str) -> WorkforcePolicyLayer:
    """Load an operator policy layer from a YAML or JSON file (fail closed)."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"workforce policy file not found: {p}")
    text = p.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text) if p.suffix in (".yaml", ".yml") else json.loads(text)
    except (yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f"workforce policy file is not valid: {exc}") from exc
    if data is None:
        return WorkforcePolicyLayer()
    if not isinstance(data, dict):
        raise ConfigError("workforce policy file must be a mapping")
    try:
        return WorkforcePolicyLayer.model_validate(data)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(f"workforce policy file failed validation: {exc}") from exc


def build_run_policy_layer(
    *,
    exclude_providers: list[str] | None = None,
    exclude_models: list[str] | None = None,
    exclude_families: list[str] | None = None,
    exclude_adapters: list[str] | None = None,
    exclude_actual_models: list[str] | None = None,
    only_providers: list[str] | None = None,
    only_models: list[str] | None = None,
    only_families: list[str] | None = None,
    allow_local: bool | None = None,
    allow_free: bool | None = None,
    allow_subscription: bool | None = None,
    allow_paid: bool | None = None,
    max_paid_cost_usd: float | None = None,
) -> WorkforcePolicyLayer:
    """Build the run-specific (CLI) policy layer from repeatable options. Only
    fields the operator actually set are populated; the rest inherit."""
    return WorkforcePolicyLayer(
        exclude_providers=list(exclude_providers or []),
        exclude_models=list(exclude_models or []),
        exclude_provider_models=list(exclude_models or []),
        exclude_families=list(exclude_families or []),
        exclude_adapters=list(exclude_adapters or []),
        exclude_actual_models=list(exclude_actual_models or []),
        only_providers=list(only_providers or []),
        only_models=list(only_models or []),
        only_families=list(only_families or []),
        allow_local=allow_local,
        allow_free=allow_free,
        allow_subscription=allow_subscription,
        allow_paid=allow_paid,
        max_paid_cost_usd=max_paid_cost_usd,
    )


def effective_policy(
    config_dir: Path | str | None = None,
    operator_policy_path: Path | str | None = None,
    run_layer: WorkforcePolicyLayer | None = None,
) -> EffectiveWorkforcePolicy:
    """Compose committed + operator-file + run-CLI layers into the effective policy
    used by every workforce operation. This is the single entry point callers use."""
    committed = committed_policy(config_dir)
    operator = load_policy_layer(operator_policy_path) if operator_policy_path else None
    return resolve_workforce_policy(committed, operator, run_layer)


def committed_policy(config_dir: Path | str | None = None) -> WorkforcePolicyLayer:
    """The committed layer: config/workforce-policy.yaml if present, else the
    provider-neutral :func:`committed_defaults`."""
    base = committed_defaults()
    if config_dir is None:
        return base
    p = Path(config_dir) / "workforce-policy.yaml"
    if not p.exists():
        return base
    override = load_policy_layer(p)
    # The committed file may only tighten/adjust the neutral base; resolve them so
    # committed-file exclusions and explicit allows apply.
    resolved = resolve_workforce_policy(base, override)
    return WorkforcePolicyLayer(
        exclude_providers=sorted(resolved.excluded_providers),
        exclude_models=sorted(resolved.excluded_models),
        exclude_provider_models=sorted(resolved.excluded_provider_models),
        exclude_families=sorted(resolved.excluded_families),
        exclude_adapters=sorted(resolved.excluded_adapters),
        exclude_actual_models=sorted(resolved.excluded_actual_models),
        only_providers=resolved.only_providers,
        only_models=resolved.only_models,
        only_families=resolved.only_families,
        only_inference_modes=resolved.only_inference_modes,
        allow_local=resolved.allow_local,
        allow_free=resolved.allow_free,
        allow_subscription=resolved.allow_subscription,
        allow_paid=resolved.allow_paid,
        max_paid_cost_usd=resolved.max_paid_cost_usd,
        max_subscription_value_usd=resolved.max_subscription_value_usd,
        max_concurrent_by_provider=resolved.max_concurrent_by_provider,
        max_requests_per_provider=resolved.max_requests_per_provider,
        max_models_assessed=resolved.max_models_assessed,
        require_verified_actual_model_for_mutation=resolved.require_verified_actual_model_for_mutation,
        require_source_containment_for_private_source=resolved.require_source_containment_for_private_source,
        require_provider_diverse_review=resolved.require_provider_diverse_review,
        require_family_diverse_review=resolved.require_family_diverse_review,
    )
