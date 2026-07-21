"""Adapter/profile capability records (final completion pass §1).

Separates MODEL COMPETENCE (proven by qualification evidence) from TRANSPORT
CAPABILITY (what an adapter can safely do). Capabilities come from the adapter
implementation + configured provider + observed evaluation evidence — never from
the provider or adapter NAME.

This replaces the old assumptions (`_ADAPTERS_WITH_BROKER_TOOLS`, `_TOOL_ROLES`,
"no chat_with_tools => planner/analyst only"). A model reachable only through a
plain `invoke` (Claude CLI, Codex CLI) is a first-class reviewer/integrator/
planner and — via bounded patch synthesis — a patch producer.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .enums import AdmissionRole, AuthMode

# Capabilities that must never be claimed just because ``invoke()`` exists — they
# are asserted only when DEMONSTRATED by real evidence (recorded in ``observed``).
_EVIDENCE_ONLY = frozenset(
    {
        "structured_output",
        "usage_reporting",
        "actual_model_reporting",
        "free_inference",
        "bounded_patch_synthesis",
    }
)


@dataclass(frozen=True)
class AdapterCapabilities:
    """A capability record with a three-way state per capability:

    * IMPLEMENTED — the boolean flag is True (the adapter code path exists).
    * OBSERVED — the name is in ``observed`` (demonstrated by real evidence).
    * UNAVAILABLE / UNKNOWN — the boolean flag is False.

    Transport gates (``plain_invoke``/``brokered_tool_loop``) are derived from real
    adapter methods, so IMPLEMENTED is sufficient. Competence-adjacent claims
    (structured output, usage/actual-model reporting, free inference, bounded patch
    synthesis) are meaningful only once OBSERVED.
    """

    plain_invoke: bool = False
    structured_output: bool = False
    usage_reporting: bool = False
    actual_model_reporting: bool = False
    native_tool_calls: bool = False  # provider-native tool-call protocol
    brokered_tool_loop: bool = False  # implements chat_with_tools for the broker
    bounded_patch_synthesis: bool = False  # can return a diff via plain invoke
    subscription_inference: bool = False
    free_inference: bool = False
    source_egress_allowed: bool = False  # set from egress policy at routing time
    observed: frozenset[str] = field(default_factory=frozenset)

    def with_egress(self, allowed: bool) -> AdapterCapabilities:
        return replace(self, source_egress_allowed=allowed)

    def with_observed(self, names: frozenset[str] | set[str]) -> AdapterCapabilities:
        return replace(self, observed=frozenset(self.observed | set(names)))

    def implemented(self, name: str) -> bool:
        return bool(getattr(self, name, False))

    def is_observed(self, name: str) -> bool:
        return name in self.observed

    def state(self, name: str) -> str:
        if not self.implemented(name):
            return "unavailable"
        return "observed" if name in self.observed else "implemented"

    def as_dict(self) -> dict[str, object]:
        """JSON-safe projection (``observed`` rendered as a sorted list)."""
        return {
            **{k: v for k, v in self.__dict__.items() if k != "observed"},
            "observed": sorted(self.observed),
        }


# Adapter construction failed / no adapter => ineligible, never assumed capable.
UNAVAILABLE = AdapterCapabilities()


def capabilities_for_kind(kind: str) -> AdapterCapabilities:
    """IMPLEMENTED capabilities for an adapter KIND, derived from the adapter
    CLASS's real methods (credential-free — no live construction). This replaces
    the old name-based ``_EDIT_CAPABLE_ADAPTERS`` set: transport is read from the
    actual class, and an unknown kind is UNAVAILABLE (never assumed capable)."""

    def _load() -> object | None:
        try:
            if kind == "openai_compatible":
                from .providers.openai_compatible import OpenAICompatibleAdapter

                return OpenAICompatibleAdapter
            if kind == "anthropic":
                from .providers.anthropic import AnthropicAdapter

                return AnthropicAdapter
            if kind == "ollama":
                from .providers.ollama import OllamaAdapter

                return OllamaAdapter
            if kind == "codex_cli":
                from .providers.cli_adapters import CodexCliAdapter

                return CodexCliAdapter
            if kind == "claude_cli":
                from .providers.cli_adapters import ClaudeCliAdapter

                return ClaudeCliAdapter
        except Exception:
            return None
        return None

    cls = _load()
    if cls is None:
        return UNAVAILABLE
    has_broker = callable(getattr(cls, "chat_with_tools", None))
    has_invoke = callable(getattr(cls, "invoke", None))
    is_cli = kind in ("codex_cli", "claude_cli")
    return AdapterCapabilities(
        plain_invoke=has_invoke,
        native_tool_calls=has_broker,
        brokered_tool_loop=has_broker,
        # CLIs edit via bounded patch synthesis (orchestrator applies + re-derives).
        bounded_patch_synthesis=is_cli,
        subscription_inference=is_cli,
    )


def capabilities_for(adapter: object, config: object | None = None) -> AdapterCapabilities:
    """Derive IMPLEMENTED capabilities from the adapter's real methods + config.

    Transport is method-derived: ``plain_invoke`` needs ``invoke``;
    ``brokered_tool_loop`` needs ``chat_with_tools``. The evidence-only capabilities
    (structured output, usage/actual-model reporting, free inference, bounded patch
    synthesis) are NOT asserted here just because ``invoke`` exists — they stay
    False until demonstrated (see ``observed_capabilities``)."""
    has_invoke = callable(getattr(adapter, "invoke", None))
    has_broker = callable(getattr(adapter, "chat_with_tools", None))
    auth = getattr(config, "auth_mode", None)
    return AdapterCapabilities(
        plain_invoke=has_invoke,
        native_tool_calls=has_broker,
        brokered_tool_loop=has_broker,
        subscription_inference=auth == AuthMode.OIDC_CLI,
        # evidence-only fields deliberately left False here.
    )


def observed_capabilities(ctx: object, provider_id: str) -> frozenset[str]:
    """Capabilities DEMONSTRATED for a provider from persisted evidence.

    Reads the latest ``provider_evaluations`` row: an EVALUATED provider has
    demonstrated structured output; a row with token usage demonstrates usage
    reporting; a verified actual model demonstrates actual-model reporting; a
    recorded free-inference row demonstrates free inference. Bounded patch
    synthesis is observed from a durable git-derived patch (recorded separately by
    the worker/candidate flow in ``capability_observations``)."""
    store = getattr(ctx, "store", None)
    if store is None:
        return frozenset()
    out: set[str] = set()
    try:
        rows = store.records("provider_evaluations", "provider_id=?", (provider_id,))
    except Exception:
        rows = []
    latest = None
    for row in rows:
        if latest is None or row.get("evaluated_at", "") > latest.get("evaluated_at", ""):
            latest = row
    if latest is not None:
        scores = latest.get("semantic_scores") or {}
        if (
            latest.get("status") == "EVALUATED"
            and float(scores.get("structured_output") or 0) >= 1.0
        ):
            out.add("structured_output")
        usage = latest.get("usage") or {}
        if int(usage.get("input_tokens") or 0) or int(usage.get("output_tokens") or 0):
            out.add("usage_reporting")
        if latest.get("actual_model_verified"):
            out.add("actual_model_reporting")
        if float(latest.get("free_inference_cost_usd") or 0) >= 0 and latest.get(
            "representative_selection_reason", ""
        ).startswith("genuinely free"):
            out.add("free_inference")
    try:
        obs = store.records("capability_observations", "provider_id=?", (provider_id,))
    except Exception:
        obs = []
    for row in obs:
        cap = row.get("capability")
        if cap:
            out.add(str(cap))
    return frozenset(out)


# Role transport/capability requirements (final completion pass §1). Model
# competence thresholds remain in the trust policy / qualification; this is only
# the TRANSPORT gate.
def role_transport_ok(role: AdmissionRole, cap: AdapterCapabilities) -> bool:
    if role in (AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PLANNER_CANDIDATE):
        return cap.plain_invoke
    if role in (AdmissionRole.REVIEWER, AdmissionRole.INTEGRATOR, AdmissionRole.ADJUDICATOR):
        # No native tool calling / chat_with_tools required — plain invoke.
        return cap.plain_invoke
    if role == AdmissionRole.PATCH_PRODUCER:
        return cap.brokered_tool_loop or cap.bounded_patch_synthesis
    if role == AdmissionRole.TRUSTED_COORDINATOR:
        return cap.plain_invoke  # high trust still gated elsewhere; not auto-granted here
    return False


def required_transport(role: AdmissionRole, cap: AdapterCapabilities) -> str:
    """The execution transport a role would use with this adapter."""
    if role == AdmissionRole.PATCH_PRODUCER:
        return "brokered_tool_loop" if cap.brokered_tool_loop else "bounded_patch_synthesis"
    return "plain_invoke"
