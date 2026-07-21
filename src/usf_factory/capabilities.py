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

from dataclasses import dataclass

from .enums import AdmissionRole, AuthMode


@dataclass(frozen=True)
class AdapterCapabilities:
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

    def with_egress(self, allowed: bool) -> AdapterCapabilities:
        return AdapterCapabilities(**{**self.__dict__, "source_egress_allowed": allowed})


def capabilities_for(adapter: object, config: object | None = None) -> AdapterCapabilities:
    """Derive capabilities from the adapter's actual methods + config auth mode.

    ``brokered_tool_loop`` requires a real ``chat_with_tools``. ``plain_invoke``
    requires ``invoke``. ``bounded_patch_synthesis`` is available whenever the
    adapter can plain-invoke (the orchestrator applies + re-derives the diff, so
    no native tool protocol is needed)."""
    has_invoke = callable(getattr(adapter, "invoke", None))
    has_broker = callable(getattr(adapter, "chat_with_tools", None))
    auth = getattr(config, "auth_mode", None)
    return AdapterCapabilities(
        plain_invoke=has_invoke,
        structured_output=True,  # every adapter returns text we parse strictly
        usage_reporting=True,  # adapters populate TokenUsage where the provider does
        actual_model_reporting=True,
        native_tool_calls=has_broker,  # native tool calls flow through chat_with_tools
        brokered_tool_loop=has_broker,
        bounded_patch_synthesis=has_invoke,
        subscription_inference=auth == AuthMode.OIDC_CLI,
        free_inference=True,
    )


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
