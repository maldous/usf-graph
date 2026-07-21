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
        from .workers import BrokeredWorker

        try:
            adapter = reg.adapter(agent.provider_id)
        except Exception:
            return _UnsupportedWorker(f"no adapter for provider {agent.provider_id}")
        chat = getattr(adapter, "chat_with_tools", None)
        if chat is None:
            return _UnsupportedWorker(
                f"provider {agent.provider_id} adapter has no brokered tool-loop"
            )
        if hasattr(adapter, "with_loop_model"):
            adapter.with_loop_model(agent.requested_model_id)
        mutating = mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)
        return BrokeredWorker(chat, store=ctx.store, mutating=mutating)

    return make


def build_engine(ctx: RuntimeContext, *, mode: RunMode | None = None):
    """Construct a fully-wired production FactoryEngine.

    Loads the materialisation index for executing modes (analysis-only; it never
    authorizes writes) and wires the production worker factory.
    """
    from .engine import FactoryEngine

    index = None
    if mode in (RunMode.SHADOW, RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE):
        try:
            from .materialisation import build_index

            index = build_index(ctx.usf_repo)
        except Exception:
            index = None
    return FactoryEngine(
        ctx, worker_factory=production_worker_factory(ctx), materialisation_index=index
    )
