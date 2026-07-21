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
        source_ok, egress_why = ctx.config.egress.source_content_allowed(agent.provider_id, privacy)

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
            # The orchestrator builds a bounded, digest-bound context pack from the
            # mirror at base_head and applies + re-derives the diff in the disposable
            # clone; the adapter (CLI) never touches the workspace or the repo.
            return AiWorker(
                adapter.invoke,
                isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
                store=ctx.store,
                ctx=ctx,
                source_content_allowed=source_ok,
                egress_reason=egress_why,
            )
        return _UnsupportedWorker(f"provider {agent.provider_id} has no safe execution transport")

    return make


def production_reviewer_factory(ctx: RuntimeContext):
    """() -> WaveReviewer | raises. Returns a factory yielding an AiReviewer
    backed by an ADMITTED reviewer-role profile, or None when no qualified
    reviewer exists — the engine then BLOCKS waves that require review (fail
    closed; approval is never synthesized)."""
    from .enums import AdmissionRole
    from .providers import build_registry
    from .review import AiReviewer

    def make():
        from .roster import roster_profile_for

        # The ACTIVE roster's reviewer (built with provider independence), else
        # any valid admitted reviewer — never first-found storage order.
        profile = roster_profile_for(ctx, AdmissionRole.REVIEWER)
        if profile is None:
            return None
        try:
            adapter = build_registry(ctx).adapter(profile.provider_id)
        except Exception:
            return None
        return AiReviewer(
            adapter.invoke,
            profile.profile_id,
            provider_id=profile.provider_id,
            model_id=profile.requested_model_id,
            adapter_id=profile.adapter,
        )

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


def select_plan_optimizer(ctx: RuntimeContext):
    """A qualified AI plan OPTIMIZER if a planner-role model is admitted, else
    None (=> the deterministic authoritative graph is used unchanged). The
    optimizer never generates obligations — it only ranks/consolidates/annotates
    the deterministic authoritative graph."""
    from .enums import AdmissionRole
    from .planner import AiPlanOptimizer
    from .providers import build_registry
    from .roster import roster_profile_for

    # ONLY the ACTIVE roster governs the planner role — never a first-found scan.
    profile = roster_profile_for(ctx, AdmissionRole.PLANNER_CANDIDATE)
    if profile is None:
        return None, None
    try:
        adapter = build_registry(ctx).adapter(profile.provider_id)
    except Exception:
        return None, None
    task_classes = list(ctx.config.task_classes.by_name())
    optimizer = AiPlanOptimizer(
        adapter.invoke,
        profile.profile_id,
        task_classes=task_classes,
        provider_id=profile.provider_id,
        model_id=profile.requested_model_id,
        adapter_id=profile.adapter,
    )
    return optimizer, profile


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


def build_engine(
    ctx: RuntimeContext, *, mode: RunMode | None = None, max_shadow_packets: int | None = None
):
    """Construct a fully-wired production FactoryEngine.

    Pipeline wiring: the deterministic authoritative planner ALWAYS, plus an
    optional AI plan OPTIMIZER (roster planner) with an INDEPENDENT planner critic
    (different provider where possible); the snapshot-bound materialisation index;
    the production worker and wave-reviewer factories.
    """
    from .engine import FactoryEngine

    materialisation_factory = None
    if mode in (RunMode.SHADOW, RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE):
        from .materialisation import build_index_at

        def materialisation_factory(mirror, head):
            return build_index_at(mirror, head)

    optimizer, optimizer_profile = select_plan_optimizer(ctx)
    critic_factory = production_planner_critic_factory(
        ctx, exclude_provider=optimizer_profile.provider_id if optimizer_profile else None
    )

    def reviewer_factory():
        return production_reviewer_factory(ctx)()

    def plan_optimizer_factory():
        opt, _ = select_plan_optimizer(ctx)
        return opt

    return FactoryEngine(
        ctx,
        planner=None,  # deterministic ProgrammePlanner is always authoritative
        plan_optimizer_factory=plan_optimizer_factory if optimizer is not None else None,
        worker_factory=production_worker_factory(ctx),
        materialisation_factory=materialisation_factory,
        reviewer_factory=reviewer_factory,
        planner_critic_factory=critic_factory if optimizer is not None else None,
        max_shadow_packets=max_shadow_packets,
    )
