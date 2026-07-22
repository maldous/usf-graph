"""Model registry: normalize discovered models into provider-independent records
and derive qualified agent-profile identities.

Provider metadata is only a claim; normalization records it as such. The agent
identity is the full tuple (provider + model + adapter + auth + tool profile +
prompt version + context/output config), so North-through-OpenCode and
North-through-another-harness are distinct profiles.
"""

from __future__ import annotations

import re

from .models import AgentProfile, DiscoveredModel, ModelRecord, ProviderConfig

_FAMILY_STRIP = re.compile(r"[:@].*$")  # drop tags like ":free", "@version"
_VERSION_SUFFIX = re.compile(r"[-_]?\d{4}[-_]?\d{2}[-_]?\d{2}$")  # trailing dates
_ROUTER_ALIASES = {"openrouter/auto", "openrouter/free"}


def canonical_family(provider_id: str, model_id: str) -> str:
    """Best-effort provider-independent family name.

    ``qwen/qwen-2.5-72b-instruct:free`` -> ``qwen-2.5-72b-instruct``.
    ``gpt-4o-2024-08-06`` -> ``gpt-4o``.
    """
    base = model_id.split("/", 1)[-1]
    base = _FAMILY_STRIP.sub("", base)
    base = _VERSION_SUFFIX.sub("", base)
    return base.strip("-_").lower() or model_id.lower()


# Broad family GROUPS for exclusion (a model belongs to one if any keyword
# appears in its provider-prefixed id). Matching is substring-based on the full
# id so ``meta-llama/llama-3.3-70b-instruct`` and ``groq/llama-3.1-8b`` both hit
# "llama", while ``mistralai/mixtral`` does not.
_FAMILY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "llama": ("llama", "meta-llama", "llama-3", "llama-4", "llama3", "llama4"),
}


def family_matches(provider_id: str, model_id: str, family: str) -> bool:
    """True iff (provider/model) belongs to the given family GROUP. The family may
    be a known group name (e.g. "llama" => any llama keyword) or a raw substring."""
    fid = f"{provider_id}/{model_id}".lower()
    fam = family.lower().strip()
    keywords = _FAMILY_KEYWORDS.get(fam, (fam,))
    return any(k in fid for k in keywords)


def is_router_alias(provider_id: str, model_id: str) -> bool:
    """Whether the requested identity delegates selection to an opaque router."""
    full = f"{provider_id}/{model_id}".lower()
    return full in _ROUTER_ALIASES or model_id.lower() in ("auto", "openrouter/auto")


def normalize_model(
    discovered: DiscoveredModel,
    config: ProviderConfig,
    *,
    catalogue_id: str = "",
    catalogue_digest: str = "",
    discovered_at: str = "",
) -> ModelRecord:
    return ModelRecord(
        provider_id=discovered.provider_id,
        requested_model_id=discovered.requested_model_id,
        canonical_family=canonical_family(discovered.provider_id, discovered.requested_model_id),
        display_name=discovered.display_name,
        actual_model_id=None,  # populated from actual receipts on invocation
        catalogue_id=catalogue_id,
        catalogue_digest=catalogue_digest,
        context_tokens=discovered.context_tokens,
        output_tokens=discovered.output_tokens,
        modalities=list(discovered.modalities),
        claims_tools=discovered.claims_tools,
        claims_structured_output=discovered.claims_structured_output,
        claims_reasoning=discovered.claims_reasoning,
        claims_streaming=discovered.claims_streaming,
        prompt_cost_per_mtok=discovered.prompt_cost_per_mtok,
        output_cost_per_mtok=discovered.output_cost_per_mtok,
        free=discovered.free,
        deprecation=discovered.deprecation,
        data_policy_class=config.privacy_class,
        adapter=config.adapter,
        config_digest=config.config_digest(),
        discovered_at=discovered_at,
    )


def default_agent_profile(record: ModelRecord, config: ProviderConfig) -> AgentProfile:
    """The default agent profile for a model record (one tool/prompt config)."""
    return AgentProfile(
        provider_id=record.provider_id,
        requested_model_id=record.requested_model_id,
        adapter=record.adapter,
        auth_mode=config.auth_mode,
        tool_profile="default",
        prompt_version="v1",
        context_config="default",
        output_config="default",
    )
