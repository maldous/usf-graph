"""The deterministic orchestration engine (DESIGN §3, all phases).

The engine owns the loop. It compiles a snapshot, plans, compiles packets,
schedules, executes (non-mutating in the safe runtime), pre-integrates, reviews,
validates, learns, and re-snapshots. Every side effect is bracketed by persisted
state transitions so the cycle is replayable and recoverable.

Safety: observe / plan-only cycles never write to /usf and never incur billable
inference. approve-wave / autonomous-safe are implemented but gated + disabled.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .authority import UsfAuthorityClient
from .conflict_graph import build_conflict_edges  # noqa: F401 (re-exported use)
from .context import RuntimeContext
from .enums import (
    AdmissionRole,
    AuthMode,
    CycleState,
    HealthStatus,
    PrivacyClass,
    ProtectedAction,
    Risk,
    RunMode,
)
from .errors import SnapshotError
from .isolation import RepoIsolation
from .learning import LearningEngine
from .materialisation import MaterialisationIndex
from .models import (
    AgentProfile,
    CycleReceipt,
    ObligationGraph,
    Packet,
    PacketResult,
    PacketSet,
    ResultQualification,
    RoutingDecision,
    SemanticSnapshot,
)
from .packet_compiler import compile_packets
from .planner import (  # noqa: F401 (FixturePlanner used by callers/tests)
    DeterministicCritic,
    FixturePlanner,
    Planner,
)
from .programme_state import ProgrammePlanner
from .result_validation import qualify_result
from .review import NoopReviewer
from .scheduler import SchedulableAgent, Scheduler
from .snapshots import compile_snapshot
from .state_machine import CycleStateMachine
from .validation import compute_terminal_complete, run_validation


def default_planner_fixture() -> Path:
    override = os.environ.get("USF_FACTORY_PLANNER_FIXTURE")
    if override:
        return Path(override)
    from .paths import repo_root

    return repo_root() / "fixtures" / "planner" / "sample-obligations.yaml"


def role_for_packet(task_class: str, has_write: bool) -> AdmissionRole:
    if task_class == "wave-review":
        return AdmissionRole.REVIEWER
    if task_class == "wave-integration":
        return AdmissionRole.INTEGRATOR
    if task_class == "semantic-planning":
        return AdmissionRole.PLANNER_CANDIDATE
    return AdmissionRole.PATCH_PRODUCER if has_write else AdmissionRole.READ_ONLY_ANALYST


class FactoryEngine:
    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        authority_factory: Callable[[], UsfAuthorityClient] = UsfAuthorityClient,
        planner: Planner | None = None,
        plan_optimizer_factory: Callable[[], object] | None = None,
        worker_factory: Callable[..., object] | None = None,
        materialisation_index: object | None = None,
        materialisation_factory: Callable[[Path, str], object] | None = None,
        reviewer_factory: Callable[[], object] | None = None,
        planner_critic_factory: Callable[[], object] | None = None,
        max_shadow_packets: int | None = None,
    ) -> None:
        self.ctx = ctx
        self.iso = RepoIsolation(ctx.paths, ctx.usf_repo)
        self._authority_factory = authority_factory
        # Production path: derive obligations deterministically from live authority
        # (ProgrammePlanner). A fixture planner is used only when injected (tests).
        # The AUTHORITATIVE graph always comes from this deterministic planner; an
        # AI optimizer (below) may only rank/annotate it, never generate it.
        self.planner = planner or ProgrammePlanner()
        # plan_optimizer_factory() -> object with async optimize(graph). Optional;
        # a failure or non-conforming optimization falls back to the deterministic
        # authoritative graph (never zero work).
        self._plan_optimizer_factory = plan_optimizer_factory
        self.critic = DeterministicCritic()
        self.learning = LearningEngine(ctx.store)
        # A worker_factory(mode, agent) -> Worker enables real execution. Without
        # one, executable modes are blocked (no live model wired in this runtime).
        self._worker_factory = worker_factory
        # Prebuilt index (tests) OR a factory building the SNAPSHOT-BOUND index
        # from the factory mirror at the exact snapshot head (production).
        self._materialisation_index = materialisation_index
        self._materialisation_factory = materialisation_factory
        # reviewer_factory() -> WaveReviewer. Waves that require substantive
        # review are BLOCKED when no reviewer is available (fail closed).
        self._reviewer_factory = reviewer_factory
        # planner_critic_factory() -> object with async review_plan(graph, proj).
        # When the planner is an AI planner, an INDEPENDENT critic (ideally a
        # different provider/family) judges the proposed plan.
        self._planner_critic_factory = planner_critic_factory
        # Shadow dispatch cap (--shadow-packets); None => no cap.
        self._max_shadow_packets = max_shadow_packets
        self._coordinator_token: int | None = None
        self._lease_lost: bool = False
        # Packets actually dispatched this wave (set by execute_packets). Missing-
        # result detection compares against THIS, never the full selected set — a
        # packet intentionally deferred by --shadow-packets is not a failure.
        self._dispatched_packet_ids: set[str] = set()

    # Executing modes (perform packet work); observe/plan-only never execute.
    _EXECUTING_MODES = (RunMode.SHADOW, RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)

    # ------------------------------------------------------------------ #
    # Phase 0 — preflight & recovery.
    # ------------------------------------------------------------------ #

    def preflight(self, cycle_id: str) -> dict[str, Any]:
        blockers: list[str] = []
        cycle_state = "READY"
        recovered_from: str | None = None
        repository_head: str | None = None

        # Crash reconciliation: reap expired leases and packet claims so a dead
        # coordinator/worker cannot hold state hostage. Fencing tokens ensure a
        # revived stale worker still cannot submit against a reclaimed packet.
        reaped_leases = self.ctx.store.reap_expired_leases()
        reaped_claims = self.ctx.store.reap_expired_claims()
        if reaped_leases or reaped_claims:
            self.ctx.log_event(
                "recovery.reaped",
                stage="INIT",
                cycle_id=cycle_id,
                payload={"leases": reaped_leases, "claims": reaped_claims},
            )

        # Detect an incomplete prior cycle.
        for c in self.ctx.store.records("cycles"):
            st = c.get("state")
            if st not in (
                CycleState.COMPLETE.value,
                CycleState.FAILED.value,
                CycleState.LEARNED.value,
            ):
                recovered_from = c.get("cycle_id")
                break
        # Ensure the factory-owned mirror (read-only fetch from /usf).
        try:
            self.iso.ensure_mirror()
            repository_head = self.iso.usf_head()
        except Exception as exc:
            cycle_state = "BLOCKED"
            blockers.append(f"mirror/inspection failed: {exc}")
        # Guard: no factory worktrees under /usf.
        stray = self.iso.assert_no_factory_worktrees()
        if stray:
            cycle_state = "BLOCKED"
            blockers.append(f"unexpected /usf worktrees: {stray}")

        result: dict[str, Any] = {
            "cycleState": cycle_state,
            "recoveredFrom": recovered_from,
            "repositoryHead": repository_head,
            "uncertainMutation": False,
            "blockers": blockers,
        }
        self.ctx.log_event("preflight", stage="INIT", cycle_id=cycle_id, payload=result)
        return result

    # ------------------------------------------------------------------ #
    # Phase 1-4 — snapshot.
    # ------------------------------------------------------------------ #

    def capture_snapshot(self, cycle_id: str) -> SemanticSnapshot:
        with self._authority_factory() as auth:
            snap = compile_snapshot(authority=auth, isolation=self.iso)
        self.ctx.store.put(
            "semantic_snapshots",
            snap.snapshot_id,
            snap.content_dict(),
            digest=snap.digest(),
            extra={
                "authority_digest": snap.authority_digest,
                "repository_head": snap.repository_head,
            },
        )
        self.ctx.log_event(
            "snapshot.captured",
            stage="SNAPSHOT",
            cycle_id=cycle_id,
            payload={
                "snapshotId": snap.snapshot_id,
                "authorityDigest": snap.authority_digest,
                "triples": snap.triple_count,
                "unresolved": len(snap.unresolved_obligations),
            },
        )
        return snap

    # ------------------------------------------------------------------ #
    # Phase 5-6 — plan + compile.
    # ------------------------------------------------------------------ #

    def _mirror_blob_digest(self, path: str, base_head: str) -> str | None:
        proc = subprocess.run(
            ["git", "-C", str(self.ctx.paths.mirror), "rev-parse", f"{base_head}:{path}"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return "git:" + proc.stdout.strip()
        return None

    def _resolve_materialisation_index(
        self, snap: SemanticSnapshot, cycle_id: str
    ) -> object | None:
        """The index used for this cycle: an injected one (tests), or one built
        from the FACTORY MIRROR at exactly ``snap.repository_head`` — never the
        live /usf working tree, so concurrent/uncommitted content cannot leak in.
        The index digest is persisted and bound into every compiled packet."""
        index = self._materialisation_index
        if index is None and self._materialisation_factory is not None:
            try:
                index = self._materialisation_factory(self.ctx.paths.mirror, snap.repository_head)
            except Exception as exc:
                self.ctx.log_event(
                    "materialisation.build_failed",
                    stage="COMPILED",
                    cycle_id=cycle_id,
                    payload={"error": str(exc)[:300]},
                )
                return None
        # Mark verified owners from stored ownership evidence (operator approvals
        # + layout-contract), so only evidence-backed owners can authorize writes.
        if isinstance(index, MaterialisationIndex):
            try:
                from .ownership import verify_index

                verify_index(self.ctx, index)
            except Exception as exc:
                self.ctx.log_event(
                    "ownership.verify_failed",
                    stage="COMPILED",
                    cycle_id=cycle_id,
                    payload={"error": str(exc)[:200]},
                )
        digest = getattr(index, "source_digest", "") if index is not None else ""
        if digest:
            self.ctx.store.put(
                "materialisation_indexes",
                digest,
                {
                    "source_digest": digest,
                    "source_commit": getattr(index, "source_commit", ""),
                    "snapshot_bound": bool(getattr(index, "snapshot_bound", False)),
                    "subjects": len(getattr(index, "entries", {})),
                },
                extra={"snapshot_id": snap.snapshot_id},
            )
        return index

    async def plan_and_compile(
        self, snap: SemanticSnapshot, cycle_id: str
    ) -> tuple[ObligationGraph, PacketSet, list[str]]:
        # 1) AUTHORITATIVE graph: always the deterministic compiler. The AI never
        #    replaces it.
        try:
            graph = await self.planner.plan(snap)
        except Exception as exc:
            self.ctx.log_event(
                "plan.authoritative_planner_failed",
                stage="PLANNED",
                cycle_id=cycle_id,
                payload={"planner": type(self.planner).__name__, "error": str(exc)[:200]},
            )
            graph = await ProgrammePlanner().plan(snap)
        authoritative_ids = {o.id for o in graph.obligations}
        # 2) Optional AI OPTIMIZER: rank/consolidate/annotate ONLY. Any failure or
        #    non-conforming result falls back to the authoritative graph — a
        #    non-empty authority plan can never be reduced to zero work.
        if self._plan_optimizer_factory is not None and graph.obligations:
            optimizer: Any = None
            try:
                optimizer = self._plan_optimizer_factory()
            except Exception:
                optimizer = None
            if optimizer is not None:
                try:
                    optimized = await optimizer.optimize(graph)
                except Exception as exc:
                    self.ctx.log_event(
                        "plan.optimizer_failed",
                        stage="PLANNED",
                        cycle_id=cycle_id,
                        payload={"error": str(exc)[:200]},
                    )
                    optimized = graph
                # Defence in depth: the optimizer must never invent or empty.
                opt_ids = {o.id for o in optimized.obligations}
                if not optimized.obligations or not opt_ids.issubset(authoritative_ids):
                    self.ctx.log_event(
                        "plan.optimizer_rejected",
                        stage="PLANNED",
                        cycle_id=cycle_id,
                        payload={
                            "reason": "empty-or-invented",
                            "authoritative": len(graph.obligations),
                        },
                    )
                else:
                    graph = optimized
        graph = self.critic.amend(graph)
        findings = list(graph.critic_findings) + self.critic.critique(graph)
        # Independent planner critic (Phase 5): a second, ideally provider-diverse
        # model judges the proposed plan. Its verdict is recorded; a rejection is
        # surfaced as a finding (the deterministic compiler stays authoritative).
        if self._planner_critic_factory is not None and graph.obligations:
            from .planner import compact_projection

            critic: Any = None
            try:
                critic = self._planner_critic_factory()
            except Exception:
                critic = None
            if critic is not None:
                verdict = await critic.review_plan(graph, compact_projection(snap))
                findings = findings + [f"planner-critic: {f}" for f in verdict.get("findings", [])]
                if not verdict.get("approved", False):
                    findings.append(
                        f"planner-critic ({verdict.get('reviewer', '?')}) withheld approval of the plan"
                    )
                self.ctx.log_event(
                    "plan.critiqued",
                    stage="PLANNED",
                    cycle_id=cycle_id,
                    payload={
                        "approved": verdict.get("approved"),
                        "reviewer": verdict.get("reviewer"),
                        "findings": verdict.get("findings", [])[:10],
                    },
                )
        graph = graph.model_copy(update={"critic_findings": findings})
        self.ctx.store.put(
            "obligation_graphs",
            graph.graph_id,
            graph.content_dict(),
            digest=graph.digest(),
            extra={"snapshot_id": snap.snapshot_id},
        )
        pset, comp_findings = compile_packets(
            graph,
            snap,
            self.ctx.config.task_classes,
            digest_fn=self._mirror_blob_digest,
            materialisation_index=self._resolve_materialisation_index(snap, cycle_id),
        )
        self.ctx.store.put(
            "packet_sets",
            pset.set_id,
            pset.content_dict(),
            digest=pset.digest(),
            extra={"snapshot_id": snap.snapshot_id, "graph_id": graph.graph_id},
        )
        for p in pset.packets:
            self.ctx.store.put(
                "packets",
                p.packet_id,
                p.content_dict(),
                digest=p.digest(),
                extra={"set_id": pset.set_id, "task_class": p.task_class},
            )
        self.ctx.log_event(
            "plan.compiled",
            stage="COMPILED",
            cycle_id=cycle_id,
            payload={
                "graphId": graph.graph_id,
                "setId": pset.set_id,
                "selected": len(pset.selected_packet_ids),
                "deferred": len(pset.deferred_packet_ids),
                "criticFindings": findings,
                "compilerFindings": comp_findings,
            },
        )
        return graph, pset, findings + comp_findings

    # ------------------------------------------------------------------ #
    # Phase 8 — schedule.
    # ------------------------------------------------------------------ #

    # Editing tools are granted to a profile whose ADAPTER CAPABILITY RECORD proves
    # a safe edit transport (brokered tool loop OR bounded patch synthesis) — never
    # by adapter name. Anything else is read-only.
    _BROKER_TOOLS = ("edit_file", "list_paths", "read_file", "run_focused_tests", "write_patch")
    _READONLY_TOOLS = ("list_paths", "read_file")

    def _capability_tools(self, profile: AgentProfile) -> list[str]:
        """Edit vs read-only tool set derived from the ACTUAL adapter capability
        record for the profile's adapter kind (never an adapter-name set). An
        unknown/unconstructable adapter is read-only (and ineligible for edit)."""
        from .capabilities import capabilities_for_kind

        cap = capabilities_for_kind(profile.adapter)
        edit_capable = cap.brokered_tool_loop or cap.bounded_patch_synthesis
        return list(self._BROKER_TOOLS if edit_capable else self._READONLY_TOOLS)

    def _model_row(self, provider_id: str, model_id: str) -> dict[str, Any] | None:
        rows = self.ctx.store.records("models", "provider_id=?", (provider_id,))
        for row in rows:
            if row.get("requested_model_id") == model_id:
                return row
        return None

    @staticmethod
    def _estimate_model_cost(row: dict[str, Any] | None) -> float:
        """Rough per-packet estimate from CATALOGUE pricing (20k prompt + 4k
        output tokens); 0.0 when no pricing is recorded."""
        if not row:
            return 0.0
        pin = float(row.get("prompt_cost_per_mtok") or 0.0)
        pout = float(row.get("output_cost_per_mtok") or 0.0)
        return (pin * 20_000 + pout * 4_000) / 1_000_000.0

    def _provider_health(self, provider_id: str) -> HealthStatus:
        """Health from the last recorded probe/refresh. UNVERIFIED providers are
        DEGRADED (still eligible, honestly labeled) — never a fabricated HEALTHY."""
        row = self.ctx.store.get("provider_health", provider_id)
        if row and row.get("status"):
            try:
                return HealthStatus(row["status"])
            except ValueError:
                pass
        return HealthStatus.DEGRADED

    def _schedulable(self, profile: AgentProfile, task_class: str) -> SchedulableAgent | None:
        """Build a SchedulableAgent from a profile IF it holds a valid admission;
        else None (revalidated at dispatch time — expired/mismatched is rejected)."""
        from .admission import admission_ineligibility

        decision, run, reason = admission_ineligibility(self.ctx, profile)
        if reason is not None or run is None or decision is None:
            if reason and reason != "no admission decision":
                self.ctx.log_event(
                    "schedule.ineligible",
                    stage="SCHEDULED",
                    cycle_id="-",
                    payload={"profile_id": profile.profile_id, "reason": reason},
                )
            return None
        cfg = self.ctx.config.providers.by_id().get(profile.provider_id)
        privacy = cfg.privacy_class if cfg else PrivacyClass.EXTERNAL_CLOUD
        scores = dict(run.get("dimension_scores", {}))
        scores.update(self.learning.scores_for(profile.profile_id, task_class))
        roles = [AdmissionRole(r) for r in decision.get("roles", [])]
        model_row = self._model_row(profile.provider_id, profile.requested_model_id)
        context_tokens = model_row.get("context_tokens") if model_row else None
        est_cost = self._estimate_model_cost(model_row)
        # Only PAID (non-free) models draw the paid budget and are gated on it.
        # SUBSCRIPTION (OIDC CLI) inference is exempt — it is authorized at the
        # adapter for the run, not drawn from the paid API budget. (A genuinely
        # free model has free is not False and is never gated here.)
        paid = model_row is not None and model_row.get("free") is False
        is_paid_api = paid and profile.auth_mode != AuthMode.OIDC_CLI
        quota_ok = True
        if is_paid_api:
            from .budget import BudgetLedger, BudgetLimits

            limits = BudgetLimits(global_usd=self.ctx.config.budgets.billable_usd)
            ledger = BudgetLedger(self.ctx.store, limits)
            remaining = limits.global_usd - ledger.spent_total()
            quota_ok = self.ctx.config.safety.allow_billable and remaining >= est_cost
        from .roster import _profile_metrics

        m = _profile_metrics(self.ctx, profile.profile_id)
        return SchedulableAgent(
            profile=profile,
            provider_id=profile.provider_id,
            admission_roles=roles,
            task_scores=scores,
            health=self._provider_health(profile.provider_id),
            privacy_class=privacy,
            context_tokens=context_tokens,
            tools=self._capability_tools(profile),
            quota_ok=quota_ok,
            cost_usd=est_cost,
            uncached_ratio=(
                m.get("uncached_per_accepted", 0.0) / max(1.0, (context_tokens or 20000))
                if m
                else 0.0
            ),
            cache_reuse=m.get("cache_reuse", 0.0) if m else 0.0,
            prior_validation_success=m.get("accepted_success", 0.0) if m else 0.0,
        )

    def _roster_profile_ids(self, role: AdmissionRole | None) -> list[str] | None:
        """The active roster's ordered candidate ids (primary + fallbacks) for a
        role, or None when no active roster / no entry — meaning the caller may
        fall back to the admitted scan (legacy / no-roster environments)."""
        if role is None:
            return None
        from .roster import active_roster

        r = active_roster(self.ctx)
        if not r:
            return None
        entry = (r.get("entries") or {}).get(role.value) or {}
        primary = entry.get("primary")
        if not primary:
            return None
        return [primary, *[p for p in entry.get("fallbacks", []) if p != primary]]

    def candidate_agents(
        self, task_class: str, role: AdmissionRole | None = None
    ) -> list[SchedulableAgent]:
        """Schedulable candidates for a role. When an ACTIVE ROSTER governs the
        role, candidates are RESTRICTED to that role's ordered entry (primary +
        fallbacks) — never an independent scan across all admitted profiles. Only
        when there is no active roster entry does it fall back to the admitted
        scan. Each candidate is revalidated (immutable, non-expired, config-matching
        qualification) and carries capability-derived tools."""
        roster_ids = self._roster_profile_ids(role)
        agents: list[SchedulableAgent] = []
        if roster_ids is not None:
            for pid in roster_ids:
                row = self.ctx.store.get("agent_profiles", pid)
                if not row:
                    continue
                agent = self._schedulable(AgentProfile(**row), task_class)
                if agent is not None:
                    agents.append(agent)
            return agents
        # No active roster entry: fall back to the admitted profiles (revalidated).
        for _key, profile_row in self.ctx.store.items("agent_profiles"):
            agent = self._schedulable(AgentProfile(**profile_row), task_class)
            if agent is not None:
                agents.append(agent)
        return agents

    def schedule_packets(self, pset: PacketSet, cycle_id: str) -> list[RoutingDecision]:
        scheduler = Scheduler(
            self.ctx.config.routing,
            self.ctx.config.egress,
            protected_allowed=self.ctx.is_gate_enabled(ProtectedAction.RISK_ACCEPTANCE),
        )
        by_id = {p.packet_id: p for p in pset.packets}
        decisions: list[RoutingDecision] = []
        for pid in pset.selected_packet_ids:
            packet = by_id[pid]
            role = role_for_packet(packet.task_class, bool(packet.write_paths))
            candidates = self.candidate_agents(packet.task_class, role)
            decision = scheduler.schedule(packet, role, candidates)
            self.ctx.store.put(
                "routing_decisions",
                f"{pid}:{cycle_id}",
                decision.model_dump(mode="json"),
                extra={"packet_id": pid},
            )
            decisions.append(decision)
        return decisions

    # ------------------------------------------------------------------ #
    # Phase 9-10 — execute (non-mutating) + qualify.
    # ------------------------------------------------------------------ #

    def _resolve_agent(self, packet_id: str, cycle_id: str) -> AgentProfile | None:
        """The agent chosen by the stored routing decision (execution is
        routing-driven — never a hard-coded worker)."""
        row = self.ctx.store.get("routing_decisions", f"{packet_id}:{cycle_id}")
        if not row or not row.get("selected_profile_id"):
            return None
        prof = self.ctx.store.get("agent_profiles", row["selected_profile_id"])
        return AgentProfile(**prof) if prof else None

    async def _execute_one(
        self, packet: Packet, cycle_id: str, mode: RunMode
    ) -> PacketResult | None:
        from .ids import run_id as make_run_id

        pid = packet.packet_id
        if self._lease_lost:
            return None  # coordinator ownership uncertain — do not dispatch

        agent = self._resolve_agent(pid, cycle_id)
        if agent is None:
            self.ctx.log_event(
                "execute.no_route",
                stage="EXECUTING",
                cycle_id=cycle_id,
                payload={"packet_id": pid, "reason": "no selected agent profile"},
            )
            return None
        if self._worker_factory is None:
            self.ctx.log_event(
                "execute.no_worker",
                stage="EXECUTING",
                cycle_id=cycle_id,
                payload={"packet_id": pid, "reason": "no worker factory wired"},
            )
            return None
        worker: Any = self._worker_factory(mode, agent)

        # Budget reservation before dispatch: the estimate comes from CATALOGUE
        # pricing (0 for free/local/unrecorded); actual cost is committed after
        # execution and the reservation released on failure.
        from .budget import BudgetLedger, BudgetLimits

        ledger = BudgetLedger(
            self.ctx.store,
            BudgetLimits(global_usd=self.ctx.config.budgets.billable_usd),
        )
        model_row = self._model_row(agent.provider_id, agent.requested_model_id)
        est = (
            self._estimate_model_cost(model_row) if (model_row or {}).get("free") is False else 0.0
        )
        ok, why = ledger.reserve(cycle_id=cycle_id, provider_id=agent.provider_id, estimate_usd=est)
        if not ok:
            self.ctx.log_event(
                "execute.budget_blocked",
                stage="EXECUTING",
                cycle_id=cycle_id,
                payload={"packet_id": pid, "reason": why},
            )
            return None

        run_id = make_run_id(cycle_id, pid)
        # Claim deadline derived from configured wall time + grace; RENEWED by a
        # per-packet heartbeat below, so a long model call cannot outlive its claim.
        claim_ttl = self.ctx.config.budgets.max_packet_wall_s + 600
        token = self.ctx.store.claim_packet_fenced(
            pid, run_id, "engine", self._lease_deadline(claim_ttl)
        )
        if token is None:
            if est:
                ledger.release(cycle_id=cycle_id, provider_id=agent.provider_id, estimate_usd=est)
            return None
        workspace = None
        result: PacketResult | None = None
        try:
            # Mutating modes need a real checkout; shadow does not mutate.
            checkout = mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)
            workspace = self.iso.create_workspace(pid, run_id, packet.base_head, checkout=checkout)
            result = await self._execute_with_claim_heartbeat(
                worker,
                packet,
                workspace,
                agent,
                pid=pid,
                run_id=run_id,
                token=token,
                claim_ttl=claim_ttl,
                cycle_id=cycle_id,
            )
            if result is None:
                return None  # fenced (claim renewal failed) or wall-clock timeout
            # Fencing: only persist if our claim token is still current AND we
            # still hold the coordinator lease.
            if self._lease_lost or not self.ctx.store.claim_token_current(pid, token):
                self.ctx.log_event(
                    "execute.fenced",
                    stage="EXECUTING",
                    cycle_id=cycle_id,
                    payload={"packet_id": pid, "reason": "stale token / lease lost"},
                )
                result = None
                return None
            self.ctx.store.put(
                "packet_results",
                f"{pid}:{run_id}",
                result.content_dict(),
                extra={"packet_id": pid, "status": result.status.value},
            )
            return result
        finally:
            # Budget: commit actual usage-derived cost, or release the reservation.
            self._settle_budget(ledger, cycle_id, agent, model_row, est, result)
            self.ctx.store.release_packet(pid, run_id)
            if workspace is not None:
                self.iso.cleanup(workspace)

    async def _execute_with_claim_heartbeat(
        self,
        worker: Any,
        packet: Packet,
        workspace: Path,
        agent: AgentProfile,
        *,
        pid: str,
        run_id: str,
        token: int,
        claim_ttl: int,
        cycle_id: str,
        interval_s: float = 30.0,
    ) -> PacketResult | None:
        """Run the worker while RENEWING its packet claim. If renewal fails the
        worker is cancelled immediately (fenced); the packet wall-clock budget is
        enforced as a hard timeout. Returns None when fenced/timed out."""
        import asyncio

        lost = asyncio.Event()

        async def _heartbeat() -> None:
            while True:
                await asyncio.sleep(interval_s)
                if not self.ctx.store.renew_claim(
                    pid, run_id, token, self._lease_deadline(claim_ttl)
                ):
                    lost.set()
                    return

        exec_task = asyncio.ensure_future(worker.execute(packet, workspace, agent))
        hb_task = asyncio.ensure_future(_heartbeat())
        lost_task = asyncio.ensure_future(lost.wait())
        try:
            done, _pending = await asyncio.wait(
                {exec_task, lost_task},
                timeout=float(self.ctx.config.budgets.max_packet_wall_s),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if exec_task in done:
                return exec_task.result()
            # Claim renewal failed OR wall-clock exceeded: cancel + fence out.
            exec_task.cancel()
            import contextlib

            with contextlib.suppress(asyncio.CancelledError, Exception):
                await exec_task
            self.ctx.log_event(
                "execute.cancelled",
                stage="EXECUTING",
                cycle_id=cycle_id,
                payload={
                    "packet_id": pid,
                    "reason": "claim renewal failed (fenced)"
                    if lost.is_set()
                    else "packet wall-clock timeout",
                },
            )
            return None
        finally:
            hb_task.cancel()
            lost_task.cancel()

    def _settle_budget(
        self,
        ledger: Any,
        cycle_id: str,
        agent: AgentProfile,
        model_row: dict[str, Any] | None,
        est: float,
        result: PacketResult | None,
    ) -> None:
        if result is None:
            if est:
                ledger.release(cycle_id=cycle_id, provider_id=agent.provider_id, estimate_usd=est)
            return
        actual = 0.0
        if model_row:
            u = result.usage or {}
            actual = (
                float(model_row.get("prompt_cost_per_mtok") or 0.0)
                * float(u.get("prompt_tokens", 0))
                + float(model_row.get("output_cost_per_mtok") or 0.0)
                * float(u.get("completion_tokens", 0))
            ) / 1_000_000.0
        if est or actual:
            ledger.commit(
                cycle_id=cycle_id,
                provider_id=agent.provider_id,
                estimate_usd=est,
                actual_usd=actual,
            )

    async def execute_packets(
        self, pset: PacketSet, mode: RunMode, cycle_id: str
    ) -> list[PacketResult]:
        import asyncio

        by_id = {p.packet_id: p for p in pset.packets}
        selected = [by_id[pid] for pid in pset.selected_packet_ids]
        # --shadow-packets N: deterministically cap the number of packets actually
        # dispatched in shadow mode (after eligibility/selection; packet identity
        # unchanged — a stable-sorted prefix of the selected set). Packets dropped
        # by the cap are INTENTIONALLY DEFERRED, not missing (see _execute_wave).
        if mode is RunMode.SHADOW and self._max_shadow_packets is not None:
            selected = sorted(selected, key=lambda p: p.packet_id)[
                : max(0, self._max_shadow_packets)
            ]
        # Record the actual dispatched set so missing-result detection compares
        # only against packets we actually tried to run.
        self._dispatched_packet_ids = {p.packet_id for p in selected}
        deferred_by_cap = [
            pid for pid in pset.selected_packet_ids if pid not in self._dispatched_packet_ids
        ]
        sem = asyncio.Semaphore(max(1, self.ctx.config.budgets.max_concurrent_workers))

        async def _guarded(packet: Packet) -> PacketResult | None:
            async with sem:
                return await self._execute_one(packet, cycle_id, mode)

        gathered = await asyncio.gather(*(_guarded(p) for p in selected))
        results = [r for r in gathered if r is not None]
        self.ctx.log_event(
            "execute.done",
            stage="EXECUTING",
            cycle_id=cycle_id,
            payload={
                "selected": len(pset.selected_packet_ids),
                "dispatched": len(self._dispatched_packet_ids),
                "deferred_by_cap": len(deferred_by_cap),
                "deferred_packet_ids": sorted(deferred_by_cap),
                "results": len(results),
                "mode": mode.value,
            },
        )
        return results

    def _record_profile_metric(
        self, result: PacketResult, task_class: str, *, accepted: bool, validated: bool
    ) -> None:
        """Persist a per-profile/per-task runtime metric row from propagated usage.
        Unknown token metrics are stored as-is (None) — never fabricated zeros."""
        import contextlib

        u = result.usage or {}
        with contextlib.suppress(Exception):
            self.ctx.store.put(
                "profile_metrics",
                f"{result.agent_profile_id}:{task_class}:{result.packet_id}",
                {
                    "agent_profile_id": result.agent_profile_id,
                    "task_class": task_class,
                    "accepted": 1 if accepted else 0,
                    "rejected": 0 if accepted else 1,
                    "semantic_validated": 1 if (accepted and validated) else 0,
                    "uncached_input_tokens": u.get("uncached_input_tokens"),
                    "cached_input_tokens": u.get("cached_input_tokens"),
                    "output_tokens": u.get("output_tokens"),
                    "latency_ms": u.get("latency_ms"),
                    "cost_usd": u.get("provider_reported_cost"),
                    "actual_model": result.actual_model,
                },
                extra={"agent_profile_id": result.agent_profile_id, "task_class": task_class},
            )

    def qualify_results(
        self, pset: PacketSet, results: list[PacketResult]
    ) -> list[ResultQualification]:
        by_id = {p.packet_id: p for p in pset.packets}
        current_head = self.iso.usf_head()
        quals: list[ResultQualification] = []
        for r in results:
            packet = by_id.get(r.packet_id)
            if packet is None:
                continue
            q = qualify_result(packet, r, current_head=current_head)
            quals.append(q)
        return quals

    # ------------------------------------------------------------------ #
    # Full cycle.
    # ------------------------------------------------------------------ #

    def _next_cycle_id(self) -> str:
        from .ids import cycle_id

        return cycle_id()

    def _lease_deadline(self, seconds: int = 900) -> str:
        from datetime import timedelta

        from .clock import utc_now

        return (utc_now() + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def _heartbeat(self, cycle_id: str, interval_s: float = 30.0) -> None:
        """Renew the coordinator lease periodically; on failure set _lease_lost."""
        import asyncio

        while True:
            await asyncio.sleep(interval_s)
            ok = self.ctx.store.renew_lease(
                "coordinator", cycle_id, self._coordinator_token or 0, self._lease_deadline()
            )
            if not ok:
                self._lease_lost = True
                self.ctx.log_event(
                    "coordinator.lease_lost",
                    stage="EXECUTING",
                    cycle_id=cycle_id,
                    payload={"reason": "UNCERTAIN_COORDINATOR_OWNERSHIP"},
                )
                return

    async def run_cycle(self, mode: RunMode) -> CycleReceipt:
        import asyncio
        import contextlib

        from .clock import utc_now_iso

        cycle_id = self._next_cycle_id()
        sm = CycleStateMachine()
        started = utc_now_iso()
        blockers: list[str] = []
        self._lease_lost = False

        # Acquire the sole coordinator lease BEFORE any state-changing preflight
        # work (lease reaping, claim reconciliation, mirror fetch) so recovery and
        # mirror mutation only ever happen under confirmed ownership. The initial
        # lease must OUTLIVE the synchronous preflight phase (mirror fetch etc.),
        # during which the heartbeat task cannot run.
        self._coordinator_token = self.ctx.store.acquire_lease(
            "coordinator",
            cycle_id,
            self._lease_deadline(self.ctx.config.budgets.max_preflight_wall_s),
        )
        if self._coordinator_token is None:
            sm.transition(CycleState.BLOCKED)
            blockers.append("another coordinator holds the active lease")
            return self._finish(cycle_id, mode, sm.state, started, blockers=blockers)

        hb = asyncio.ensure_future(self._heartbeat(cycle_id))
        try:
            pre = self.preflight(cycle_id)  # now runs UNDER the coordinator lease
            if pre["cycleState"] == "BLOCKED":
                sm.transition(CycleState.BLOCKED)
                return self._finish(cycle_id, mode, sm.state, started, blockers=pre["blockers"])
            return await self._run_cycle_leased(mode, cycle_id, sm, started, blockers)
        finally:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await hb
            self.ctx.store.release_lease("coordinator", cycle_id, self._coordinator_token)

    async def _run_cycle_leased(self, mode, cycle_id, sm, started, blockers):
        sm.transition(CycleState.READY)

        # Snapshot (fails closed: a degraded/synthesized authority blocks the cycle).
        sm.transition(CycleState.SNAPSHOT)
        try:
            snap = self.capture_snapshot(cycle_id)
        except SnapshotError as exc:
            sm.transition(CycleState.BLOCKED)
            blockers.append(f"snapshot failed closed: {exc}")
            self.ctx.log_event(
                "snapshot.blocked", stage="SNAPSHOT", cycle_id=cycle_id, payload={"error": str(exc)}
            )
            return self._finish(cycle_id, mode, sm.state, started, blockers=blockers)

        # Plan + compile (report proposed packets in all modes).
        sm.transition(CycleState.PLANNED)
        graph, pset, _findings = await self.plan_and_compile(snap, cycle_id)
        sm.transition(CycleState.COMPILED)
        no_progress = self._detect_no_progress(snap, pset)

        # OBSERVE: snapshot + plan/compile report only. No scheduling/execution.
        if mode is RunMode.OBSERVE:
            sm.transition(CycleState.LEARNED)
            self._eval_terminal(snap, cycle_id)
            return self._finish(
                cycle_id,
                mode,
                sm.state,
                started,
                snapshot=snap,
                graph=graph,
                pset=pset,
                no_progress=no_progress,
                blockers=blockers,
            )

        # Schedule (route simulation) in all remaining modes.
        sm.transition(CycleState.SCHEDULED)
        self.schedule_packets(pset, cycle_id)

        # PLAN_ONLY: stop after routing. No model mutation.
        if mode is RunMode.PLAN_ONLY:
            sm.transition(CycleState.LEARNED)
            self._eval_terminal(snap, cycle_id)
            if no_progress:
                blockers.append("no progress vs previous cycle")
            return self._finish(
                cycle_id,
                mode,
                sm.state,
                started,
                snapshot=snap,
                graph=graph,
                pset=pset,
                no_progress=no_progress,
                blockers=blockers,
            )

        # Executing modes (shadow / approve-wave / autonomous-safe).
        if (
            mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE)
            and not self.ctx.config.safety.autonomous_safe_enabled
        ):
            sm.transition(CycleState.BLOCKED)
            blockers.append(
                f"mode '{mode.value}' requires autonomous_safe_enabled=true (disabled by default)"
            )
            return self._finish(
                cycle_id,
                mode,
                sm.state,
                started,
                snapshot=snap,
                graph=graph,
                pset=pset,
                blockers=blockers,
            )
        if self._worker_factory is None:
            sm.transition(CycleState.BLOCKED)
            blockers.append(
                f"mode '{mode.value}' needs a wired worker runtime; none available "
                f"(no live/local model + billable disabled) — ENVIRONMENT_BLOCKED"
            )
            return self._finish(
                cycle_id,
                mode,
                sm.state,
                started,
                snapshot=snap,
                graph=graph,
                pset=pset,
                blockers=blockers,
            )

        return await self._execute_wave(
            mode, cycle_id, sm, started, snap, graph, pset, no_progress, blockers
        )

    def _eval_terminal(self, snap: SemanticSnapshot, cycle_id: str) -> None:
        complete, reasons = compute_terminal_complete(self.ctx, snap)
        self.ctx.log_event(
            "terminal.evaluated",
            stage="LEARNED",
            cycle_id=cycle_id,
            payload={"complete": complete, "reasons": reasons},
        )

    async def _execute_wave(
        self, mode, cycle_id, sm, started, snap, graph, pset, no_progress, blockers
    ):
        from .attribution import is_worker_fault
        from .integration import deterministic_preintegrate

        sm.transition(CycleState.EXECUTING)
        results = await self.execute_packets(pset, mode, cycle_id)
        quals = self.qualify_results(pset, results)
        by_id = {p.packet_id: p for p in pset.packets}
        results_by_pid = {r.packet_id: r for r in results}
        accepted = [q for q in quals if q.accepted]
        accepted_results = [results_by_pid[q.packet_id] for q in accepted]

        # WORKER FAILURES are recorded immediately (fair: worker-fault only).
        # SUCCESS is credited ONLY after the wave integrates AND validates.
        for q in quals:
            r = results_by_pid.get(q.packet_id)
            pkt = by_id.get(q.packet_id)
            if r is None or pkt is None or q.accepted:
                continue
            if q.failure_class is not None and is_worker_fault(q.failure_class):
                self.learning.record_worker_outcome(
                    r.agent_profile_id,
                    pkt.task_class,
                    accepted=False,
                    failure_class=q.failure_class,
                )
                self.learning.observe(
                    "worker", r.agent_profile_id, pkt.task_class, "implementation", 0.0
                )

        # DISPATCHED packets that produced no result (no route / fenced / no worker)
        # ARE failures. Packets intentionally deferred by the --shadow-packets cap
        # were never dispatched, so they are NOT missing — deferred != failed.
        dispatched = self._dispatched_packet_ids or set(pset.selected_packet_ids)
        missing = [pid for pid in dispatched if pid not in results_by_pid]
        deferred_by_cap = [pid for pid in pset.selected_packet_ids if pid not in dispatched]

        # FAIL-CLOSED: every DISPATCHED packet's result must be ACCEPTED. A recorded
        # failure, rejection, human-decision, or skip can never yield a green
        # cycle — a failed result being durably recorded is not success.
        rejected = [q for q in quals if not q.accepted]

        # Wave accounting: selected / dispatched / intentionally-deferred / completed
        # / failed are reported distinctly (deferred is never counted as failed).
        self.ctx.log_event(
            "execute.accounting",
            stage="EXECUTING",
            cycle_id=cycle_id,
            payload={
                "selected": len(pset.selected_packet_ids),
                "dispatched": len(dispatched),
                "deferred_by_cap": sorted(deferred_by_cap),
                "completed": sorted(q.packet_id for q in accepted),
                "failed": sorted([*(q.packet_id for q in rejected), *missing]),
            },
        )

        sm.transition(CycleState.INTEGRATING)
        apply = mode in (RunMode.APPROVE_WAVE, RunMode.AUTONOMOUS_SAFE) and not self._lease_lost

        def _fetch(r: PacketResult) -> str:
            return self.ctx.store.cas_get(r.patch_ref).decode() if r.patch_ref else ""

        attempt, wave = deterministic_preintegrate(
            pset.set_id,
            accepted_results,
            self.iso,
            base_head=snap.repository_head,
            patch_fetch=_fetch if apply else None,
            apply_patches=apply,
            store=self.ctx.store,
        )
        self.ctx.store.put(
            "integration_attempts",
            pset.set_id,
            attempt.content_dict(),
            extra={"set_id": pset.set_id},
        )
        if wave is not None:
            self.ctx.store.put(
                "wave_patches",
                wave.patch_digest,
                wave.content_dict(),
                extra={"set_id": pset.set_id},
            )
        integration_failed = bool(accepted_results) and not attempt.deterministic_merge_ok

        # VALIDATE FIRST so the reviewer receives the actual validation evidence.
        sm.transition(CycleState.VALIDATING)
        receipt = self._validate_wave(pset, wave, snap)
        self.ctx.store.put(
            "validation_receipts",
            pset.set_id,
            receipt.content_dict(),
            extra={"set_id": pset.set_id},
        )
        validation_failed = wave is not None and not receipt.all_passed

        sm.transition(CycleState.REVIEWING)
        # SUBSTANTIVE review is required for EVERY wave patch unless every
        # selected packet is explicitly low-risk mechanical work: semantic
        # subjects, high/protected risk, or non-mechanical medium risk all
        # demand a real reviewer. No reviewer available => BLOCKED (fail closed);
        # an explicit reviewer rejection also blocks. The reviewer gets the ACTUAL
        # diff + semantic delta + validation evidence via the context bundle.
        needs_review = wave is not None and self._wave_requires_review(pset, by_id)
        reviewer: Any = None
        if needs_review and self._reviewer_factory is not None:
            try:
                reviewer = self._reviewer_factory()
            except Exception:
                reviewer = None
        bundle = (
            self._build_review_bundle(pset, wave, receipt, accepted_results)
            if wave is not None
            else None
        )
        review = await (reviewer if reviewer is not None else NoopReviewer()).review(
            pset.set_id, wave, bundle
        )
        self.ctx.store.put(
            "wave_reviews",
            f"{pset.set_id}:{review.reviewer_profile_id}",
            review.content_dict(),
            extra={"set_id": pset.set_id},
        )
        review_unavailable = needs_review and reviewer is None
        review_rejected = needs_review and reviewer is not None and not review.approved

        # Post-wave re-snapshot (read-only) before terminal evaluation.
        try:
            post = self.capture_snapshot(cycle_id)
        except Exception:
            post = snap

        # Per-profile/per-task runtime metrics (accepted/rejected + token/cache/cost/
        # latency from the propagated usage). Unknown metrics stay unrecorded (not
        # fabricated zeros); they feed roster ranking tie-breaks.
        validated = bool(getattr(receipt, "all_passed", False))
        for q in quals:
            r = results_by_pid.get(q.packet_id)
            pkt = by_id.get(q.packet_id)
            if r is not None and pkt is not None:
                self._record_profile_metric(
                    r, pkt.task_class, accepted=q.accepted, validated=validated
                )

        # Fail-closed terminal decision.
        fail_reasons: list[str] = []
        if self._lease_lost:
            fail_reasons.append("coordinator ownership uncertain")
        if missing:
            fail_reasons.append(f"{len(missing)} selected packet(s) produced no result")
        for q in rejected:
            why = "; ".join(q.reasons) or (
                q.failure_class.value if q.failure_class else "not accepted"
            )
            fail_reasons.append(f"packet {q.packet_id} result not accepted: {why}")
        if integration_failed:
            fail_reasons.append(f"integration failed: {attempt.semantic_conflicts}")
        if review_unavailable:
            fail_reasons.append("required substantive review unavailable for this wave")
        if review_rejected:
            fail_reasons.append(f"review rejected the wave: {review.risk_flags or review.findings}")
        if validation_failed:
            fail_reasons.append("required validation failed")

        if fail_reasons:
            sm.transition(CycleState.BLOCKED)
            blockers.extend(fail_reasons)
            return self._finish(
                cycle_id,
                mode,
                sm.state,
                started,
                snapshot=post,
                graph=graph,
                pset=pset,
                accepted=0,
                no_progress=no_progress,
                blockers=blockers,
            )

        # SUCCESS: the wave integrated and validated. Credit accepted workers now.
        for q in accepted:
            r = results_by_pid[q.packet_id]
            pkt = by_id[q.packet_id]
            self.learning.record_worker_outcome(
                r.agent_profile_id, pkt.task_class, accepted=True, failure_class=None
            )
            self.learning.observe(
                "worker", r.agent_profile_id, pkt.task_class, "implementation", 1.0
            )

        if wave is not None and receipt.all_passed:
            from .delivery import prepare_delivery

            art = prepare_delivery(self.ctx, wave, post, receipt)
            self.ctx.store.put(
                "publication_receipts",
                f"{pset.set_id}:delivery",
                {"prepared": art.prepared, "reason": art.reason},
                extra={"set_id": pset.set_id},
            )

        sm.transition(CycleState.LEARNED)
        self._eval_terminal(post, cycle_id)
        if no_progress:
            blockers.append("no progress vs previous cycle")
        return self._finish(
            cycle_id,
            mode,
            sm.state,
            started,
            snapshot=post,
            graph=graph,
            pset=pset,
            accepted=len(accepted),
            no_progress=no_progress,
            blockers=blockers,
        )

    def _build_review_bundle(self, pset, wave, receipt, accepted_results=None):
        """Bounded ReviewContextBundle carrying the ACTUAL effective diff, the
        patch-derived semantic delta, validation gates and worker attribution."""
        from .review import ReviewContextBundle
        from .semantic_delta import extract_semantic_delta

        diff = ""
        if wave is not None and getattr(wave, "patch_ref", None):
            try:
                diff = self.ctx.store.cas_get(wave.patch_ref).decode()
            except Exception:
                diff = ""
        delta = extract_semantic_delta(diff).to_dict() if diff else {}
        by_id = {p.packet_id: p for p in pset.packets}
        objectives = [by_id[pid].objective for pid in pset.selected_packet_ids if pid in by_id]
        criteria = sorted(
            {
                c
                for pid in pset.selected_packet_ids
                if pid in by_id
                for c in by_id[pid].acceptance_criteria
            }
        )
        attribution = {}
        for r in accepted_results or []:
            attribution[r.packet_id] = f"{r.actual_provider or '?'}/{r.actual_model or '?'}"
        return ReviewContextBundle(
            set_id=pset.set_id,
            packet_objectives=objectives,
            acceptance_criteria=criteria,
            effective_diff=diff,
            semantic_delta=delta,
            validation_gates=dict(receipt.gates) if receipt is not None else {},
            worker_attribution=attribution,
        )

    def _wave_requires_review(self, pset: PacketSet, by_id: dict[str, Packet]) -> bool:
        """True unless EVERY selected packet is explicitly low-risk mechanical."""
        tc = self.ctx.config.task_classes.by_name()
        for pid in pset.selected_packet_ids:
            p = by_id[pid]
            if p.risk in (Risk.HIGH, Risk.PROTECTED):
                return True
            if p.semantic_subjects:
                return True
            task = tc.get(p.task_class)
            if p.risk is not Risk.LOW and not (task and task.mechanical):
                return True
        return False

    def _validate_wave(self, pset, wave, snap):
        """Run required validation profiles for the wave against the integration
        clone. A required gate with no runner FAILS (never green-skip)."""
        from .validation_runners import build_runners

        if wave is None:
            return run_validation(pset.set_id, [])  # nothing produced to validate
        gates = sorted({g for p in pset.packets for g in p.required_validation})
        clone_path = self.ctx.paths.integration / pset.set_id
        runners = build_runners(clone_path)
        return run_validation(pset.set_id, gates, runners)

    def _detect_no_progress(self, snap: SemanticSnapshot, pset: PacketSet) -> bool:
        prev = self.ctx.store.records("cycles")
        if not prev:
            return False
        last = sorted(prev, key=lambda c: c.get("cycle_id", ""))[-1]
        return (
            last.get("snapshot_id") == snap.snapshot_id
            and last.get("selected_packets", -1) == len(pset.selected_packet_ids)
            and len(pset.selected_packet_ids) == 0
        )

    def _finish(
        self,
        cycle_id: str,
        mode: RunMode,
        state: CycleState,
        started: str,
        *,
        snapshot: SemanticSnapshot | None = None,
        graph: ObligationGraph | None = None,
        pset: PacketSet | None = None,
        accepted: int = 0,
        no_progress: bool = False,
        blockers: list[str] | None = None,
    ) -> CycleReceipt:
        from .clock import utc_now_iso

        receipt = CycleReceipt(
            cycle_id=cycle_id,
            mode=mode.value,
            state=state,
            snapshot_id=snapshot.snapshot_id if snapshot else None,
            graph_id=graph.graph_id if graph else None,
            set_id=pset.set_id if pset else None,
            selected_packets=len(pset.selected_packet_ids) if pset else 0,
            accepted_packets=accepted,
            published=False,
            no_progress=no_progress,
            blockers=blockers or [],
            started_at=started,
            ended_at=utc_now_iso(),
        )
        self.ctx.store.put(
            "cycles",
            cycle_id,
            receipt.content_dict(),
            extra={"state": state.value},
        )
        self.ctx.log_event(
            "cycle.finished",
            stage=state.value,
            cycle_id=cycle_id,
            payload={"state": state.value, "mode": mode.value, "blockers": receipt.blockers},
        )
        return receipt
