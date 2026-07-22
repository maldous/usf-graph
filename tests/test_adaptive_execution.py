"""Adaptive nondeterministic execution and deterministic simulation evidence."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from usf_factory.adaptive_execution import (
    AdaptiveExecutionController,
    ResourceSnapshot,
    SimulationPoint,
    WorkloadIdentity,
    choose_operating_point,
    compare_strategies,
    workload_identity,
)
from usf_factory.canonical import content_digest
from usf_factory.config import load_config
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AuthMode, PacketResultStatus, Risk, RunMode
from usf_factory.event_store import open_store
from usf_factory.models import AgentProfile, Packet, PacketResult, PacketSet

HEALTHY = ResourceSnapshot()


def _packet(name: str, *, task_class: str = "semantic-planning") -> Packet:
    return Packet(
        obligation_id=name,
        snapshot_id="snapshot",
        authority_digest="sha256:" + "a" * 64,
        base_head="b" * 40,
        objective="bounded analysis",
        task_class=task_class,
        risk=Risk.LOW,
        data_classification="public",
    )


def _agent() -> AgentProfile:
    return AgentProfile(
        provider_id="fixture-provider",
        requested_model_id="fixture-model",
        adapter="ollama",
        auth_mode=AuthMode.LOCAL,
    )


def _observation(level: int, *, validated: bool = True, **overrides):
    row = {
        "offered_concurrency": level,
        "elapsed_s": 10.0,
        "accepted": validated,
        "validated": validated,
        "timed_out": False,
        "throttled": False,
        "malformed": False,
        "semantic_rejected": not validated,
        "resource_pressure": 0.0,
        "downstream_backlog_ratio": 0.0,
    }
    row.update(overrides)
    return row


@pytest.mark.adversarial
def test_atomic_admission_allows_only_one_racer(tmp_path):
    database = tmp_path / "adaptive.sqlite"
    cas = tmp_path / "cas"
    first = open_store(database, cas)
    try:
        tokens = {
            "p1": first.claim_packet_fenced("p1", "r1", "coordinator", "2999-01-01T00:00:00Z"),
            "p2": first.claim_packet_fenced("p2", "r2", "coordinator", "2999-01-01T00:00:00Z"),
        }
        coordinator_token = first.acquire_lease(
            "coordinator", "coordinator", "2999-01-01T00:00:00Z"
        )
        assert coordinator_token is not None
        decision = content_digest({"level": 1})
        state = {
            "controller_session": "session",
            "permitted_active": 1,
            "decision_digest": decision,
        }
        first.put(
            "adaptive_controller_states",
            "session",
            state,
            extra={"controller_session": "session"},
        )

        def admit(packet_id, run_id):
            worker_store = open_store(database, cas)
            try:
                return worker_store.try_admit_invocation(
                    attempt_id=f"attempt-{packet_id}",
                    packet_id=packet_id,
                    run_id=run_id,
                    claim_token=int(tokens[packet_id] or 0),
                    coordinator_owner="coordinator",
                    coordinator_token=coordinator_token,
                    controller_session="session",
                    workload_key="workload",
                    provider_id="provider",
                    permitted_active=1,
                    decision_digest=decision,
                    payload={},
                )
            finally:
                worker_store.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda args: admit(*args), (("p1", "r1"), ("p2", "r2"))))
        assert sum(value is not None for value in outcomes) == 1
        assert first.count("adaptive_invocations", "status='active'") == 1
    finally:
        first.close()


@pytest.mark.adversarial
def test_same_packet_cannot_have_two_active_invocations(ctx):
    packet = _packet("packet-one")
    token = ctx.store.claim_packet_fenced(
        packet.packet_id, "run", "coordinator", "2999-01-01T00:00:00Z"
    )
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert coordinator_token is not None
    decision = content_digest({"level": 2})
    ctx.store.put(
        "adaptive_controller_states",
        "session",
        {"permitted_active": 2, "decision_digest": decision},
        extra={"controller_session": "session"},
    )
    first = ctx.store.try_admit_invocation(
        attempt_id="attempt-one",
        packet_id=packet.packet_id,
        run_id="run",
        claim_token=int(token or 0),
        coordinator_owner="coordinator",
        coordinator_token=coordinator_token,
        controller_session="session",
        workload_key="workload",
        provider_id="provider",
        permitted_active=2,
        decision_digest=decision,
        payload={},
    )
    second = ctx.store.try_admit_invocation(
        attempt_id="attempt-two",
        packet_id=packet.packet_id,
        run_id="run",
        claim_token=int(token or 0),
        coordinator_owner="coordinator",
        coordinator_token=coordinator_token,
        controller_session="session",
        workload_key="workload",
        provider_id="provider",
        permitted_active=2,
        decision_digest=decision,
        payload={},
    )
    assert first is not None and second is None


@pytest.mark.adversarial
def test_controller_sessions_share_one_atomic_active_invocation_limit(ctx):
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert coordinator_token is not None
    decision = content_digest({"level": 1})
    for session in ("first-session", "second-session"):
        ctx.store.put(
            "adaptive_controller_states",
            session,
            {"permitted_active": 1, "decision_digest": decision},
            extra={"controller_session": session},
        )
    outcomes = []
    for index, session in enumerate(("first-session", "second-session")):
        packet = _packet(f"cross-session-{index}")
        run_id = f"run-{index}"
        claim = ctx.store.claim_packet_fenced(
            packet.packet_id, run_id, "coordinator", "2999-01-01T00:00:00Z"
        )
        outcomes.append(
            ctx.store.try_admit_invocation(
                attempt_id=f"attempt-{index}",
                packet_id=packet.packet_id,
                run_id=run_id,
                claim_token=int(claim or 0),
                coordinator_owner="coordinator",
                coordinator_token=coordinator_token,
                controller_session=session,
                workload_key="workload",
                provider_id="provider",
                permitted_active=1,
                decision_digest=decision,
                payload={},
            )
        )
    assert sum(token is not None for token in outcomes) == 1


@pytest.mark.adversarial
def test_adaptive_queue_fails_closed_when_claim_is_fenced(ctx):
    controller = AdaptiveExecutionController(
        ctx.store,
        session_id="fenced",
        resource_sampler=lambda: HEALTHY,
        random_float=lambda: 0.5,
    )
    packet = _packet("fenced-packet")
    claim = ctx.store.claim_packet_fenced(
        packet.packet_id, "run", "coordinator", "2999-01-01T00:00:00Z"
    )
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert claim is not None and coordinator_token is not None
    ctx.store.release_packet(packet.packet_id, "run")
    with pytest.raises(RuntimeError, match="ADAPTIVE_PACKET_CLAIM_FENCED"):
        asyncio.run(
            controller.acquire(
                packet=packet,
                agent=_agent(),
                run_id="run",
                claim_token=claim,
                coordinator_owner="coordinator",
                coordinator_token=coordinator_token,
            )
        )


@pytest.mark.adversarial
def test_validation_credit_binds_only_the_exact_successful_redraw(ctx):
    controller = AdaptiveExecutionController(ctx.store, session_id="credit")
    packet = _packet("credit-packet")
    run_id = "credit-run"
    claim = ctx.store.claim_packet_fenced(
        packet.packet_id, run_id, "coordinator", "2999-01-01T00:00:00Z"
    )
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert claim is not None and coordinator_token is not None
    decision_digest = content_digest({"level": 1})
    ctx.store.put(
        "adaptive_controller_states",
        "credit",
        {"permitted_active": 1, "decision_digest": decision_digest},
        extra={"controller_session": "credit"},
    )
    profiles = [
        _agent(),
        _agent().model_copy(
            update={"provider_id": "second-provider", "requested_model_id": "second-model"}
        ),
    ]
    for index, profile in enumerate(profiles):
        attempt_id = f"attempt-{index}"
        admission = ctx.store.try_admit_invocation(
            attempt_id=attempt_id,
            packet_id=packet.packet_id,
            run_id=run_id,
            claim_token=claim,
            coordinator_owner="coordinator",
            coordinator_token=coordinator_token,
            controller_session="credit",
            workload_key="workload",
            provider_id=profile.provider_id,
            permitted_active=1,
            decision_digest=decision_digest,
            payload={"agent_profile_id": profile.profile_id},
        )
        assert admission is not None
        assert ctx.store.settle_invocation(
            attempt_id=attempt_id,
            admission_token=admission,
            status="failed" if index == 0 else "completed",
            observation={"workload_key": "workload", "validated": None, "accepted": None},
        )
    controller.record_validated_outcome(
        packet.packet_id,
        attempt_id="attempt-1",
        accepted=True,
        validated=True,
        independently_reviewed=True,
    )
    assert ctx.store.get("adaptive_observations", "attempt-0")["validated"] is None
    assert ctx.store.get("adaptive_observations", "attempt-1")["validated"] is True


@pytest.mark.e2e
async def test_same_model_invocations_overlap_only_for_distinct_packets(ctx):
    controller = AdaptiveExecutionController(
        ctx.store, session_id="session", resource_sampler=lambda: HEALTHY, random_float=lambda: 0.5
    )
    packets = [_packet("first"), _packet("second")]
    agent = _agent()
    identity = workload_identity(packets[0], agent, HEALTHY)
    for level in (1, 2):
        observation = {
            **_observation(level),
            "workload_key": identity.key,
            "provider_id": agent.provider_id,
            "actual_model": agent.requested_model_id,
            "task_class": packets[0].task_class,
        }
        ctx.store.put(
            "adaptive_observations",
            f"seed-{level}",
            observation,
            extra={
                "workload_key": identity.key,
                "provider_id": agent.provider_id,
                "actual_model": agent.requested_model_id,
                "task_class": packets[0].task_class,
            },
        )
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert coordinator_token is not None
    claims: list[int] = []
    for index, packet in enumerate(packets):
        token = ctx.store.claim_packet_fenced(
            packet.packet_id, f"run-{index}", "coordinator", "2999-01-01T00:00:00Z"
        )
        assert token is not None
        claims.append(token)

    active_packets: set[str] = set()
    observed_packets: set[str] = set()
    both_started = asyncio.Event()
    maximum_active = 0

    async def invoke(index: int) -> None:
        nonlocal maximum_active
        packet = packets[index]
        admission = await controller.acquire(
            packet=packet,
            agent=agent,
            run_id=f"run-{index}",
            claim_token=claims[index],
            coordinator_owner="coordinator",
            coordinator_token=coordinator_token,
        )
        attempt_id, token, admitted_identity, decision, concurrency, queue_delay = admission
        assert admitted_identity.provider_id == agent.provider_id
        assert admitted_identity.requested_model == agent.requested_model_id
        active_packets.add(packet.packet_id)
        observed_packets.add(packet.packet_id)
        maximum_active = max(maximum_active, len(active_packets))
        if len(active_packets) == 2:
            both_started.set()
        await asyncio.wait_for(both_started.wait(), timeout=1.0)
        result = PacketResult(
            packet_id=packet.packet_id,
            execution_attempt_id=attempt_id,
            status=PacketResultStatus.COMPLETED,
            agent_profile_id=agent.profile_id,
            actual_provider=agent.provider_id,
            actual_model=agent.requested_model_id,
        )
        controller.settle(
            attempt_id=attempt_id,
            admission_token=token,
            identity=admitted_identity,
            decision=decision,
            active_concurrency=concurrency,
            packet=packet,
            result=result,
            reason="ok",
            queue_delay_s=queue_delay,
            elapsed_s=0.1,
        )
        active_packets.remove(packet.packet_id)

    await asyncio.gather(*(invoke(index) for index in range(len(packets))))
    assert maximum_active == 2
    assert observed_packets == {packet.packet_id for packet in packets}
    assert ctx.store.count("adaptive_invocations", "status='active'") == 0


@pytest.mark.adversarial
def test_restart_fences_old_invocations_and_restarts_at_one(ctx):
    old = AdaptiveExecutionController(ctx.store, session_id="old")
    packet = _packet("old")
    claim = ctx.store.claim_packet_fenced(packet.packet_id, "run", "old", "2999-01-01T00:00:00Z")
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    assert coordinator_token is not None
    decision = content_digest({"level": 5})
    ctx.store.put(
        "adaptive_controller_states",
        "old",
        {"permitted_active": 5, "decision_digest": decision},
        extra={"controller_session": "old"},
    )
    assert ctx.store.try_admit_invocation(
        attempt_id="old-attempt",
        packet_id=packet.packet_id,
        run_id="run",
        claim_token=int(claim or 0),
        coordinator_owner="coordinator",
        coordinator_token=coordinator_token,
        controller_session="old",
        workload_key="workload",
        provider_id="provider",
        permitted_active=5,
        decision_digest=decision,
        payload={},
    )
    assert ctx.store.renew_claim(packet.packet_id, "run", int(claim or 0), "2000-01-01T00:00:00Z")
    new = AdaptiveExecutionController(
        ctx.store, session_id="new", resource_sampler=lambda: HEALTHY, random_float=lambda: 0.5
    )
    assert ctx.store.reap_expired_claims() == [packet.packet_id]
    assert new.reconcile_after_restart() == {"fenced": ["old-attempt"], "pending": []}
    identity = WorkloadIdentity(
        "provider", "model", "task", "low", "small", "analysis", False, False, "healthy"
    )
    assert new.decision(identity, risk=Risk.LOW).permitted_active == 1
    assert old.session_id != new.session_id


@pytest.mark.adversarial
def test_restart_does_not_duplicate_an_unreconciled_live_invocation(ctx):
    packet = _packet("pending-old")
    claim = ctx.store.claim_packet_fenced(packet.packet_id, "run", "old", "2999-01-01T00:00:00Z")
    coordinator_token = ctx.store.acquire_lease(
        "coordinator", "coordinator", "2999-01-01T00:00:00Z"
    )
    decision = content_digest({"level": 1})
    ctx.store.put(
        "adaptive_controller_states",
        "old",
        {"permitted_active": 1, "decision_digest": decision},
        extra={"controller_session": "old"},
    )
    assert claim is not None and coordinator_token is not None
    assert ctx.store.try_admit_invocation(
        attempt_id="pending-attempt",
        packet_id=packet.packet_id,
        run_id="run",
        claim_token=claim,
        coordinator_owner="coordinator",
        coordinator_token=coordinator_token,
        controller_session="old",
        workload_key="workload",
        provider_id="provider",
        permitted_active=1,
        decision_digest=decision,
        payload={},
    )
    new = AdaptiveExecutionController(ctx.store, session_id="new")
    assert new.reconcile_after_restart() == {
        "fenced": [],
        "pending": ["pending-attempt"],
    }
    assert ctx.store.get("adaptive_invocations", "pending-attempt")["status"] == "active"


@pytest.mark.adversarial
def test_conflicting_selected_packets_never_overlap(ctx):
    first, second = _packet("first"), _packet("second")
    first.conflicts_with = [second.packet_id]
    pset = PacketSet(
        snapshot_id="snapshot",
        graph_id="graph",
        packets=[first, second],
        selected_packet_ids=[first.packet_id, second.packet_id],
    )
    with pytest.raises(RuntimeError, match="CONFLICTING_PACKET_SELECTION"):
        asyncio.run(FactoryEngine(ctx).execute_packets(pset, RunMode.SHADOW, "cycle"))
    assert ctx.store.count("adaptive_invocations") == 0


@pytest.mark.unit
def test_fixed_concurrency_is_not_a_configuration_surface():
    config = load_config()
    assert not hasattr(config.budgets, "max_concurrent_workers")
    assert "max_concurrent_by_provider" not in config.model_dump(mode="json")


SCENARIOS = {
    "linear-saturation": {
        1: SimulationPoint(10),
        2: SimulationPoint(10),
        3: SimulationPoint(10),
        4: SimulationPoint(10),
        5: SimulationPoint(12),
    },
    "unknown-throttle": {
        1: SimulationPoint(10),
        2: SimulationPoint(10),
        3: SimulationPoint(10),
        4: SimulationPoint(10, throttle_probability=0.8),
        5: SimulationPoint(10, throttle_probability=1.0),
    },
    "latency-rises-throughput-improves": {
        1: SimulationPoint(8),
        2: SimulationPoint(10),
        3: SimulationPoint(13),
        4: SimulationPoint(18),
    },
    "aggregate-overload": {
        1: SimulationPoint(10),
        2: SimulationPoint(12),
        3: SimulationPoint(18),
        4: SimulationPoint(40),
    },
    "quality-before-latency": {
        1: SimulationPoint(10),
        2: SimulationPoint(10),
        3: SimulationPoint(10, validation_probability=0.60),
        4: SimulationPoint(10, validation_probability=0.35),
    },
    "gpu-exhaustion": {
        1: SimulationPoint(8),
        2: SimulationPoint(8),
        3: SimulationPoint(9),
        4: SimulationPoint(9, resource_pressure=1.0),
    },
    "background-host-load": {
        1: SimulationPoint(9),
        2: SimulationPoint(10),
        3: SimulationPoint(12, resource_pressure=0.8),
        4: SimulationPoint(18, resource_pressure=1.0),
    },
    "mixed-context-heavy": {
        1: SimulationPoint(15),
        2: SimulationPoint(22),
        3: SimulationPoint(40),
        4: SimulationPoint(70),
    },
    "downstream-bottleneck": {
        1: SimulationPoint(8),
        2: SimulationPoint(8, downstream_backlog=1.0),
        3: SimulationPoint(8, downstream_backlog=1.0),
    },
}


@pytest.mark.parametrize(("name", "curve"), SCENARIOS.items())
@pytest.mark.unit
def test_comparative_simulation_discovers_condition_specific_load(name, curve):
    report = compare_strategies(curve, steps=100)
    adaptive = report["adaptive"]
    best_fixed = max(row["validated_per_minute"] for row in report["fixed"])
    assert adaptive["validated_per_minute"] >= best_fixed * 0.70, name
    assert adaptive["duplicate_packets"] == 0
    assert adaptive["conflicting_overlaps"] == 0
    assert adaptive["authorization_violations"] == 0
    assert len(set(adaptive["tested_levels"])) > 1


@pytest.mark.unit
def test_provider_recovery_and_continuous_adjacent_probing():
    observations = [
        _observation(1),
        _observation(2),
        _observation(3, throttled=True, validated=False),
        _observation(3),
        _observation(3),
        _observation(3),
    ]
    recovered = choose_operating_point(
        observations,
        current_level=2,
        resources=HEALTHY,
        explore_draw=0.5,
        exploration_allowed=True,
    )
    assert recovered.permitted_active >= 2
    probe = choose_operating_point(
        [_observation(1), _observation(2)],
        current_level=2,
        resources=HEALTHY,
        explore_draw=0.01,
        exploration_allowed=True,
    )
    assert probe.exploring is True and probe.permitted_active in {1, 3}


@pytest.mark.unit
def test_utility_uses_actual_active_load_not_unused_permission():
    decision = choose_operating_point(
        [
            {
                **_observation(7),
                "active_concurrency": 1,
                "offered_concurrency": 7,
            }
        ],
        current_level=1,
        resources=HEALTHY,
        explore_draw=0.5,
        exploration_allowed=False,
    )
    assert set(decision.utility_by_level) == {1}


@pytest.mark.unit
def test_quality_resource_and_backpressure_degrade_before_raw_throughput():
    quality = choose_operating_point(
        [_observation(1), _observation(2), _observation(3, validated=False)],
        current_level=3,
        resources=HEALTHY,
        explore_draw=0.5,
        exploration_allowed=True,
    )
    assert quality.permitted_active < 3
    distressed = choose_operating_point(
        [_observation(1), _observation(2)],
        current_level=4,
        resources=ResourceSnapshot(gpu_allocation_failure=True),
        explore_draw=0.5,
        exploration_allowed=True,
    )
    assert distressed.permitted_active == 2


@pytest.mark.unit
def test_workload_profiles_do_not_share_learned_capacity(ctx):
    controller = AdaptiveExecutionController(
        ctx.store,
        session_id="segmented",
        resource_sampler=lambda: HEALTHY,
        random_float=lambda: 0.5,
    )
    short = WorkloadIdentity("p", "m", "short", "low", "small", "analysis", False, False, "healthy")
    heavy = WorkloadIdentity("p", "m", "heavy", "low", "large", "artifact", True, True, "healthy")
    for index, level in enumerate((1, 2, 3)):
        row = {
            **_observation(level),
            "workload_key": short.key,
            "provider_id": "p",
            "task_class": "short",
        }
        ctx.store.put(
            "adaptive_observations",
            f"short-{index}",
            row,
            extra={
                "workload_key": short.key,
                "provider_id": "p",
                "actual_model": "m",
                "task_class": "short",
            },
        )
    assert controller.decision(short, risk=Risk.LOW).permitted_active > 1
    assert controller.decision(heavy, risk=Risk.MEDIUM).permitted_active == 1
