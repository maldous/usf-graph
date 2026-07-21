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
    RunMode,
)
from .errors import SnapshotError
from .isolation import RepoIsolation
from .learning import LearningEngine
from .models import (
    AgentProfile,
    CycleReceipt,
    ObligationGraph,
    PacketResult,
    PacketSet,
    ResultQualification,
    RoutingDecision,
    SemanticSnapshot,
)
from .packet_compiler import compile_packets
from .planner import DeterministicCritic, FixturePlanner, Planner
from .result_validation import qualify_result
from .review import NoopReviewer
from .scheduler import SchedulableAgent, Scheduler
from .snapshots import compile_snapshot
from .state_machine import CycleStateMachine
from .validation import compute_terminal_complete, run_validation
from .workers import DryRunWorker


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
    ) -> None:
        self.ctx = ctx
        self.iso = RepoIsolation(ctx.paths, ctx.usf_repo)
        self._authority_factory = authority_factory
        self.planner = planner or FixturePlanner(default_planner_fixture())
        self.critic = DeterministicCritic()
        self.learning = LearningEngine(ctx.store)
        self._coordinator_token: int | None = None

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

    async def plan_and_compile(
        self, snap: SemanticSnapshot, cycle_id: str
    ) -> tuple[ObligationGraph, PacketSet, list[str]]:
        graph = await self.planner.plan(snap)
        graph = self.critic.amend(graph)
        findings = self.critic.critique(graph)
        graph = graph.model_copy(update={"critic_findings": findings})
        self.ctx.store.put(
            "obligation_graphs",
            graph.graph_id,
            graph.content_dict(),
            digest=graph.digest(),
            extra={"snapshot_id": snap.snapshot_id},
        )
        pset, comp_findings = compile_packets(
            graph, snap, self.ctx.config.task_classes, digest_fn=self._mirror_blob_digest
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

    def candidate_agents(self, task_class: str) -> list[SchedulableAgent]:
        """Build schedulable candidates from stored qualification runs + learning."""
        runs = self.ctx.store.records("qualification_runs")
        provs = self.ctx.config.providers.by_id()
        agents: list[SchedulableAgent] = []
        for run in runs:
            profile_row = self.ctx.store.get("agent_profiles", run["agent_profile_id"])
            if not profile_row:
                continue
            profile = AgentProfile(**profile_row)
            cfg = provs.get(profile.provider_id)
            privacy = cfg.privacy_class if cfg else PrivacyClass.EXTERNAL_CLOUD
            scores = dict(run.get("dimension_scores", {}))
            scores.update(self.learning.scores_for(run["agent_profile_id"], task_class))
            roles = [AdmissionRole(r) for r in run.get("roles_admitted", [])]
            agents.append(
                SchedulableAgent(
                    profile=profile,
                    provider_id=profile.provider_id,
                    admission_roles=roles,
                    task_scores=scores,
                    health=HealthStatus.HEALTHY,
                    privacy_class=privacy,
                    context_tokens=None,
                    tools=["*"],
                )
            )
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
            candidates = self.candidate_agents(packet.task_class)
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

    async def execute_packets(
        self, pset: PacketSet, mode: RunMode, cycle_id: str
    ) -> list[PacketResult]:
        from .ids import run_id as make_run_id

        worker = DryRunWorker()  # safe runtime: no mutation, no billable inference
        by_id = {p.packet_id: p for p in pset.packets}
        results: list[PacketResult] = []
        for pid in pset.selected_packet_ids:
            packet = by_id[pid]
            run_id = make_run_id(cycle_id, pid)
            # One claim authority — refuse double dispatch — with a fencing token.
            token = self.ctx.store.claim_packet_fenced(
                pid, run_id, "engine", self._lease_deadline()
            )
            if token is None:
                continue
            workspace = None
            try:
                workspace = self.iso.create_workspace(pid, run_id, packet.base_head)
                agent = AgentProfile(
                    provider_id="dry-run",
                    requested_model_id="dry-run",
                    adapter="dry_run",
                    auth_mode=AuthMode.LOCAL,
                )
                result = await worker.execute(packet, workspace, agent)
                # Fencing: only persist if our claim token is still current (a
                # crashed/expired worker whose packet was reclaimed is rejected).
                if self.ctx.store.claim_token_current(pid, token):
                    self.ctx.store.put(
                        "packet_results",
                        f"{pid}:{run_id}",
                        result.content_dict(),
                        extra={"packet_id": pid, "status": result.status.value},
                    )
                    results.append(result)
                else:
                    self.ctx.log_event(
                        "execute.fenced",
                        stage="EXECUTING",
                        cycle_id=cycle_id,
                        payload={"packet_id": pid, "reason": "stale claim token"},
                    )
            finally:
                self.ctx.store.release_packet(pid, run_id)
                if workspace is not None:
                    self.iso.cleanup(workspace)
        self.ctx.log_event(
            "execute.done",
            stage="EXECUTING",
            cycle_id=cycle_id,
            payload={"results": len(results), "mode": mode.value},
        )
        return results

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

    async def run_cycle(self, mode: RunMode) -> CycleReceipt:
        from .clock import utc_now_iso

        cycle_id = self._next_cycle_id()
        sm = CycleStateMachine()
        started = utc_now_iso()
        blockers: list[str] = []

        pre = self.preflight(cycle_id)
        if pre["cycleState"] == "BLOCKED":
            sm.transition(CycleState.BLOCKED)
            return self._finish(cycle_id, mode, sm.state, started, blockers=pre["blockers"])

        # One claim authority: acquire the sole coordinator lease (fencing token).
        self._coordinator_token = self.ctx.store.acquire_lease(
            "coordinator", cycle_id, self._lease_deadline()
        )
        if self._coordinator_token is None:
            sm.transition(CycleState.BLOCKED)
            blockers.append("another coordinator holds the active lease")
            return self._finish(cycle_id, mode, sm.state, started, blockers=blockers)
        try:
            return await self._run_cycle_leased(mode, cycle_id, sm, started, blockers)
        finally:
            self.ctx.store.release_lease("coordinator", cycle_id, self._coordinator_token)

    async def _run_cycle_leased(self, mode, cycle_id, sm, started, blockers):
        from .clock import utc_now_iso  # noqa: F401

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

        # Plan + compile.
        sm.transition(CycleState.PLANNED)
        graph, pset, _findings = await self.plan_and_compile(snap, cycle_id)
        sm.transition(CycleState.COMPILED)

        # No-progress detection.
        no_progress = self._detect_no_progress(snap, pset)

        # Schedule.
        sm.transition(CycleState.SCHEDULED)
        self.schedule_packets(pset, cycle_id)

        if mode in (RunMode.OBSERVE, RunMode.PLAN_ONLY):
            # Complete the non-mutating pipeline for observability.
            sm.transition(CycleState.EXECUTING)
            results = await self.execute_packets(pset, mode, cycle_id)
            sm.transition(CycleState.INTEGRATING)
            quals = self.qualify_results(pset, results)
            accepted = [q for q in quals if q.accepted]
            from .integration import deterministic_preintegrate

            attempt, wave = deterministic_preintegrate(
                pset.set_id,
                [r for r in results if r.packet_id in {q.packet_id for q in accepted}],
                self.iso,
                base_head=snap.repository_head,
            )
            self.ctx.store.put(
                "integration_attempts",
                pset.set_id,
                attempt.content_dict(),
                extra={"set_id": pset.set_id},
            )
            sm.transition(CycleState.REVIEWING)
            review = await NoopReviewer().review(pset.set_id, wave)
            self.ctx.store.put(
                "wave_reviews",
                f"{pset.set_id}:{review.reviewer_profile_id}",
                review.content_dict(),
                extra={"set_id": pset.set_id},
            )
            sm.transition(CycleState.VALIDATING)
            receipt = run_validation(pset.set_id, [])  # nothing to validate (no wave patch)
            self.ctx.store.put(
                "validation_receipts",
                pset.set_id,
                receipt.content_dict(),
                extra={"set_id": pset.set_id},
            )
            sm.transition(CycleState.LEARNED)
            # No worker outcomes to learn from in a dry-run (no accepted mutations).
            complete, reasons = compute_terminal_complete(self.ctx, snap)
            self.ctx.log_event(
                "terminal.evaluated",
                stage="LEARNED",
                cycle_id=cycle_id,
                payload={"complete": complete, "reasons": reasons},
            )
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
                accepted=len(accepted),
                no_progress=no_progress,
                blockers=blockers,
            )

        # approve-wave / autonomous-safe: gated + disabled in the safe runtime.
        if not self.ctx.config.safety.autonomous_safe_enabled:
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

        # (Reached only when explicitly enabled by an operator — still never
        # mutates /usf here; execution uses isolated clones and gated integration.)
        sm.transition(CycleState.BLOCKED)
        blockers.append("mutating execution not implemented in this runtime")
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
