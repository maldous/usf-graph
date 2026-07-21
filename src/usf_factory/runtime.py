"""Production runtime wiring (review §2 / blocker 2).

Builds a `FactoryEngine` wired for real execution — a `worker_factory` that turns
a routed agent profile into a brokered executor backed by the provider adapter,
plus (for executing modes) the materialisation index. This is what the installed
`usf-factory` CLI uses, so the execution path is not injection-only.

Live execution still requires a reachable model + billing; without them the
adapter's tool-loop chat raises and the packet fails closed (ENVIRONMENT_BLOCKED),
which the engine turns into a BLOCKED cycle — never a false success.
"""

from __future__ import annotations

from .context import RuntimeContext
from .enums import FailureClass, PacketResultStatus, RunMode
from .models import AgentProfile, Packet, PacketResult


class _UnsupportedWorker:
    """Fail-closed worker for adapters without a brokered tool-loop."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    async def execute(self, packet: Packet, workspace, agent: AgentProfile) -> PacketResult:
        from .clock import utc_now_iso

        return PacketResult(
            packet_id=packet.packet_id,
            status=PacketResultStatus.FAILED,
            agent_profile_id=agent.profile_id,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            failure_class=FailureClass.ADAPTER_ERROR,
            failure_detail=self.reason[:500],
            produced_at=utc_now_iso(),
        )


def production_worker_factory(ctx: RuntimeContext):
    """(mode, agent) -> Worker, using the provider adapter's tool-loop chat."""
    from .providers import build_registry

    reg = build_registry(ctx)

    def make(mode: RunMode, agent: AgentProfile):
        from .capabilities import capabilities_for
        from .enums import PrivacyClass
        from .isolation import RepoIsolation
        from .workers import AiWorker, BrokeredWorker

        try:
            adapter = reg.adapter(agent.provider_id)
        except Exception:
            return _UnsupportedWorker(f"no adapter for provider {agent.provider_id}")
        pcfg = ctx.config.providers.by_id().get(agent.provider_id)
        cap = (
            adapter.capabilities()
            if hasattr(adapter, "capabilities")
            else capabilities_for(adapter, pcfg)
        )
        mutating = mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)
        privacy = (pcfg.privacy_class if pcfg else PrivacyClass.EXTERNAL_CLOUD).value
        source_ok, _why = ctx.config.egress.source_content_allowed(agent.provider_id, privacy)

        # Prefer the brokered tool loop; else the bounded context-and-patch worker
        # (AiWorker) — Claude/Codex CLIs are first-class producers this way; else
        # fail closed.
        if cap.brokered_tool_loop:
            if hasattr(adapter, "with_loop_model"):
                adapter.with_loop_model(agent.requested_model_id)
            return BrokeredWorker(
                adapter.chat_with_tools,  # type: ignore[attr-defined]
                store=ctx.store,
                mutating=mutating,
                source_content_allowed=source_ok,
            )
        if cap.bounded_patch_synthesis:
            # The orchestrator applies + re-derives the diff in the disposable
            # clone; the adapter (CLI) never touches the workspace.
            return AiWorker(
                adapter.invoke, isolation=RepoIsolation(ctx.paths, ctx.usf_repo), store=ctx.store
            )
        return _UnsupportedWorker(f"provider {agent.provider_id} has no safe execution transport")

    return make


def production_reviewer_factory(ctx: RuntimeContext):
    """() -> WaveReviewer | raises. Returns a factory yielding an AiReviewer
    backed by an ADMITTED reviewer-role profile, or None when no qualified
    reviewer exists — the engine then BLOCKS waves that require review (fail
    closed; approval is never synthesized)."""
    from .enums import AdmissionRole
    from .models import AgentProfile
    from .providers import build_registry
    from .review import AiReviewer

    def make():
        from .admission import admission_ineligibility

        for _key, row in ctx.store.items("agent_profiles"):
            profile = AgentProfile(**row)
            decision, _run, reason = admission_ineligibility(ctx, profile)
            if reason is not None or decision is None:
                continue
            if AdmissionRole.REVIEWER.value not in set(decision.get("roles", [])):
                continue
            try:
                adapter = build_registry(ctx).adapter(profile.provider_id)
            except Exception:
                continue
            return AiReviewer(
                adapter.invoke,
                profile.profile_id,
                provider_id=profile.provider_id,
                model_id=profile.requested_model_id,
                adapter_id=profile.adapter,
            )
        return None

    return make


def _admitted_profiles(ctx: RuntimeContext, role):
    """Profiles holding a valid admission for ``role`` (provider-diverse selection
    material). Returns list of (profile, provider_family)."""
    from .admission import admission_ineligibility
    from .models import AgentProfile

    out = []
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, _run, reason = admission_ineligibility(ctx, profile)
        if reason is not None or decision is None:
            continue
        if role.value in set(decision.get("roles", [])):
            out.append(profile)
    return out


def select_planner(ctx: RuntimeContext):
    """A qualified AI planner if one is admitted, else None (=> deterministic
    ProgrammePlanner + read-only diagnostics)."""
    from .enums import AdmissionRole
    from .planner import OBLIGATION_GRAPH_SCHEMA, AiPlanner
    from .providers import build_registry

    for profile in _admitted_profiles(ctx, AdmissionRole.PLANNER_CANDIDATE):
        try:
            adapter = build_registry(ctx).adapter(profile.provider_id)
        except Exception:
            continue
        planner = AiPlanner(
            adapter.invoke,
            profile.profile_id,
            OBLIGATION_GRAPH_SCHEMA,
            provider_id=profile.provider_id,
            model_id=profile.requested_model_id,
            adapter_id=profile.adapter,
        )
        return planner, profile
    return None, None


def production_planner_critic_factory(ctx: RuntimeContext, exclude_provider: str | None = None):
    """() -> planner critic. Prefers an admitted REVIEWER on a DIFFERENT provider
    than the planner; falls back to the deterministic critic adapter."""
    from .enums import AdmissionRole
    from .planner import AiPlannerCritic, DeterministicCriticAdapter
    from .providers import build_registry

    def make():
        for profile in _admitted_profiles(ctx, AdmissionRole.REVIEWER):
            if exclude_provider and profile.provider_id == exclude_provider:
                continue
            try:
                adapter = build_registry(ctx).adapter(profile.provider_id)
            except Exception:
                continue
            return AiPlannerCritic(
                adapter.invoke,
                profile.profile_id,
                provider_id=profile.provider_id,
                model_id=profile.requested_model_id,
            )
        return DeterministicCriticAdapter()

    return make


def build_engine(ctx: RuntimeContext, *, mode: RunMode | None = None):
    """Construct a fully-wired production FactoryEngine.

    Pipeline wiring: a qualified AI planner (when admitted) with an INDEPENDENT
    planner critic (different provider where possible); the snapshot-bound
    materialisation index; the production worker and wave-reviewer factories.
    """
    from .engine import FactoryEngine

    materialisation_factory = None
    if mode in (RunMode.SHADOW, RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE):
        from .materialisation import build_index_at

        def materialisation_factory(mirror, head):
            return build_index_at(mirror, head)

    planner, planner_profile = select_planner(ctx)
    critic_factory = production_planner_critic_factory(
        ctx, exclude_provider=planner_profile.provider_id if planner_profile else None
    )

    def reviewer_factory():
        return production_reviewer_factory(ctx)()

    return FactoryEngine(
        ctx,
        planner=planner,  # None => deterministic ProgrammePlanner (read-only diagnostics)
        worker_factory=production_worker_factory(ctx),
        materialisation_factory=materialisation_factory,
        reviewer_factory=reviewer_factory,
        planner_critic_factory=critic_factory if planner is not None else None,
    )
