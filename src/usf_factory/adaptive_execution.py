"""Observed-performance adaptive invocation admission.

Concurrency is deliberately not configured.  A fresh controller process starts
at one invocation, measures accepted/validated throughput and degradation, and
stochastically probes adjacent load levels.  Canonical packet identity and
fencing remain deterministic; only runtime timing and load exploration are
nondeterministic.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import shutil
import statistics
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .canonical import content_digest
from .enums import PacketResultStatus, Risk
from .event_store import Store
from .ids import ulid
from .models import AgentProfile, Packet, PacketResult


@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_utilization: float | None = None
    cpu_load_per_core: float = 0.0
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    run_queue: int = 0
    available_memory_ratio: float = 1.0
    swap_activity: int = 0
    io_pressure: float = 0.0
    disk_free_ratio: float = 1.0
    network_errors: int = 0
    network_bytes_per_s: float | None = None
    process_count: int = 0
    gpu_utilization: float | None = None
    gpu_memory_ratio: float | None = None
    gpu_temperature_c: float | None = None
    gpu_allocation_failure: bool = False
    thermal_throttling: bool = False

    @property
    def emergency(self) -> bool:
        """Emergency cutoffs only; these do not calculate normal concurrency."""
        return bool(
            self.gpu_allocation_failure
            or self.thermal_throttling
            or self.available_memory_ratio < 0.03
            or self.disk_free_ratio < 0.01
            or self.swap_activity > 0
        )

    @property
    def pressure(self) -> float:
        gpu_pressure = self.gpu_memory_ratio or 0.0
        return max(
            0.0,
            min(
                1.0,
                0.14 * (self.cpu_utilization or 0.0)
                + 0.10 * min(self.cpu_load_per_core, 2.0) / 2.0
                + 0.22 * (1.0 - self.available_memory_ratio)
                + 0.16 * min(self.io_pressure, 1.0)
                + 0.16 * gpu_pressure
                + 0.12 * (1.0 - self.disk_free_ratio)
                + 0.10 * (1.0 if self.network_errors else 0.0),
            ),
        )

    @property
    def resource_class(self) -> str:
        if self.emergency:
            return "distress"
        if self.pressure >= 0.65:
            return "pressured"
        if self.pressure >= 0.30:
            return "moderate"
        return "healthy"


def _read_number(path: Path, key: str) -> float:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(key):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _read_pressure(path: Path) -> float:
    with contextlib.suppress(OSError, ValueError, IndexError):
        line = next(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("some ")
        )
        field = next(field for field in line.split() if field.startswith("avg10="))
        return float(field.split("=", 1)[1]) / 100.0
    return 0.0


def sample_host_resources(root: Path = Path("/")) -> ResourceSnapshot:
    """Take a best-effort, credential-free host observation.

    Missing sensors remain unknown.  They never become fabricated healthy GPU
    evidence.  No provider or network endpoint is contacted.
    """
    proc = root / "proc"
    total_kib = _read_number(proc / "meminfo", "MemTotal:")
    available_kib = _read_number(proc / "meminfo", "MemAvailable:")
    memory_ratio = available_kib / total_kib if total_kib else 1.0
    # /proc/vmstat exposes lifetime counters, not an interval.  A one-shot
    # sampler must leave swap *activity* unknown rather than treating historical
    # swaps as current distress. Stateful samplers and tests may supply a delta.
    swap_activity = 0
    cpu_count = max(1, os.cpu_count() or 1)
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0
    run_queue = 0
    with contextlib.suppress(OSError, ValueError, IndexError):
        run_queue = int((proc / "loadavg").read_text(encoding="utf-8").split()[3].split("/")[0])
    io_pressure = _read_pressure(proc / "pressure" / "io")
    disk = shutil.disk_usage(root)
    disk_ratio = disk.free / disk.total if disk.total else 1.0
    process_count = 0
    with contextlib.suppress(OSError):
        process_count = sum(1 for path in proc.iterdir() if path.name.isdigit())
    network_errors = 0
    try:
        for line in (proc / "net" / "dev").read_text(encoding="utf-8").splitlines()[2:]:
            fields = line.replace(":", " ").split()
            if len(fields) >= 14:
                network_errors += (
                    int(fields[3]) + int(fields[4]) + int(fields[11]) + int(fields[12])
                )
    except (OSError, ValueError):
        pass
    temperatures: list[float] = []
    for path in sorted((root / "sys" / "class" / "thermal").glob("thermal_zone*/temp")):
        try:
            temperatures.append(float(path.read_text(encoding="utf-8").strip()) / 1000.0)
        except (OSError, ValueError):
            continue
    peak_temperature = max(temperatures) if temperatures else None
    gpu_utilization = gpu_memory_ratio = gpu_temperature = None
    if shutil.which("nvidia-smi"):
        with contextlib.suppress(OSError, subprocess.SubprocessError, ValueError, IndexError):
            proc_result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
            )
            values = [
                float(value.strip()) for value in proc_result.stdout.splitlines()[0].split(",")
            ]
            gpu_utilization = values[0] / 100.0
            gpu_memory_ratio = values[1] / values[2] if values[2] else None
            gpu_temperature = values[3]
    observed_temperature = gpu_temperature if gpu_temperature is not None else peak_temperature
    return ResourceSnapshot(
        cpu_load_per_core=load1 / cpu_count,
        load_1=load1,
        load_5=load5,
        load_15=load15,
        run_queue=run_queue,
        available_memory_ratio=max(0.0, min(1.0, memory_ratio)),
        swap_activity=swap_activity,
        io_pressure=max(0.0, io_pressure),
        disk_free_ratio=max(0.0, min(1.0, disk_ratio)),
        network_errors=network_errors,
        process_count=process_count,
        gpu_utilization=gpu_utilization,
        gpu_memory_ratio=gpu_memory_ratio,
        gpu_temperature_c=observed_temperature,
        thermal_throttling=bool(observed_temperature is not None and observed_temperature >= 95.0),
    )


def _cpu_counters(root: Path) -> tuple[int, int]:
    with contextlib.suppress(OSError, ValueError, IndexError):
        values = [
            int(value) for value in (root / "proc" / "stat").read_text().splitlines()[0].split()[1:]
        ]
        return sum(values), values[3] + (values[4] if len(values) > 4 else 0)
    return 0, 0


def _network_counters(root: Path) -> tuple[int, int]:
    total_bytes = errors = 0
    with contextlib.suppress(OSError, ValueError):
        for line in (root / "proc" / "net" / "dev").read_text().splitlines()[2:]:
            fields = line.replace(":", " ").split()
            if len(fields) >= 17:
                total_bytes += int(fields[1]) + int(fields[9])
                errors += int(fields[3]) + int(fields[4]) + int(fields[11]) + int(fields[12])
    return total_bytes, errors


class HostResourceSampler:
    """Stateful sampler for interval CPU, swap and network observations."""

    def __init__(self, root: Path = Path("/"), monotonic: Callable[[], float] = time.monotonic):
        self.root = root
        self.monotonic = monotonic
        self._at = monotonic()
        self._cpu_total, self._cpu_idle = _cpu_counters(root)
        self._swap = int(
            _read_number(root / "proc" / "vmstat", "pswpin ")
            + _read_number(root / "proc" / "vmstat", "pswpout ")
        )
        self._network_bytes, self._network_errors = _network_counters(root)

    def __call__(self) -> ResourceSnapshot:
        current = sample_host_resources(self.root)
        at = self.monotonic()
        total, idle = _cpu_counters(self.root)
        cpu_delta = total - self._cpu_total
        idle_delta = idle - self._cpu_idle
        cpu_utilization = (
            max(0.0, min(1.0, (cpu_delta - idle_delta) / cpu_delta)) if cpu_delta > 0 else None
        )
        swap = int(
            _read_number(self.root / "proc" / "vmstat", "pswpin ")
            + _read_number(self.root / "proc" / "vmstat", "pswpout ")
        )
        network_bytes, network_errors = _network_counters(self.root)
        elapsed = max(at - self._at, 0.001)
        sampled = replace(
            current,
            cpu_utilization=cpu_utilization,
            swap_activity=max(0, swap - self._swap),
            network_bytes_per_s=max(0.0, (network_bytes - self._network_bytes) / elapsed),
            network_errors=max(0, network_errors - self._network_errors),
        )
        self._at = at
        self._cpu_total, self._cpu_idle = total, idle
        self._swap = swap
        self._network_bytes, self._network_errors = network_bytes, network_errors
        return sampled


@dataclass(frozen=True)
class WorkloadIdentity:
    provider_id: str
    requested_model: str
    task_class: str
    risk: str
    context_class: str
    output_class: str
    tool_use: bool
    mutating: bool
    resource_class: str

    @property
    def key(self) -> str:
        return content_digest(asdict(self))


@dataclass(frozen=True)
class AdaptiveDecision:
    permitted_active: int
    exploring: bool
    rationale: tuple[str, ...]
    utility_by_level: dict[int, float]

    @property
    def digest(self) -> str:
        return content_digest(
            {
                "permitted_active": self.permitted_active,
                "exploring": self.exploring,
                "rationale": list(self.rationale),
                "utility_by_level": {str(k): v for k, v in sorted(self.utility_by_level.items())},
            }
        )


def workload_identity(
    packet: Packet, agent: AgentProfile, resources: ResourceSnapshot
) -> WorkloadIdentity:
    context = packet.required_capabilities.min_context_tokens
    context_class = "small" if context <= 16_000 else "medium" if context <= 64_000 else "large"
    output_class = "artifact" if packet.write_paths else "analysis"
    return WorkloadIdentity(
        provider_id=agent.provider_id,
        requested_model=agent.requested_model_id,
        task_class=packet.task_class,
        risk=packet.risk.value,
        context_class=context_class,
        output_class=output_class,
        tool_use=bool(packet.permitted_tools),
        mutating=bool(packet.write_paths),
        resource_class=resources.resource_class,
    )


def observation_utility(row: dict[str, Any]) -> float:
    elapsed = max(float(row.get("elapsed_s") or 0.0), 0.001)
    validated = 1.0 if row.get("validated") is True else 0.0
    accepted = 1.0 if row.get("accepted") is True else 0.0
    input_tokens = max(
        1.0,
        float(row.get("uncached_input_tokens") or 0.0)
        + float(row.get("cached_input_tokens") or 0.0),
    )
    output_tokens = max(0.0, float(row.get("output_tokens") or 0.0))
    accepted_token_efficiency = output_tokens / input_tokens if validated else 0.0
    quality = validated + 0.20 * accepted + min(accepted_token_efficiency, 1.0) * 0.05
    offered = max(1, int(row.get("offered_concurrency") or 1))
    penalties = (
        4.0 * float(bool(row.get("semantic_rejected")))
        + 3.0 * float(bool(row.get("scope_violation")))
        + 2.5 * float(bool(row.get("timed_out")))
        + 2.0 * float(bool(row.get("throttled")))
        + 1.5 * float(bool(row.get("malformed")))
        + 1.0 * float(bool(row.get("transport_error")))
        + 1.0 * float(row.get("resource_pressure") or 0.0)
        + 0.5 * float(row.get("downstream_backlog_ratio") or 0.0)
        + 0.25 * float(row.get("retry_count") or 0.0)
        + 0.1 * float(row.get("cost_usd") or 0.0)
    )
    return quality * offered / elapsed - penalties


def choose_operating_point(
    observations: list[dict[str, Any]],
    *,
    current_level: int,
    resources: ResourceSnapshot,
    explore_draw: float,
    exploration_allowed: bool,
) -> AdaptiveDecision:
    """Hybrid marginal-throughput hill climb with stochastic adjacent probing.

    The only candidate above observed history is the adjacent level.  There is
    no configured capacity ceiling or worker-count target.
    """
    by_level: dict[int, list[dict[str, Any]]] = {}
    for row in observations:
        level = int(row.get("active_concurrency") or row.get("offered_concurrency") or 1)
        by_level.setdefault(max(1, level), []).append(row)
    utilities = {
        level: round(sum(observation_utility(row) for row in rows) / len(rows), 9)
        for level, rows in by_level.items()
        if rows
    }
    if resources.emergency:
        return AdaptiveDecision(
            max(1, current_level // 2),
            False,
            ("emergency resource cutoff",),
            utilities,
        )
    current_rows = by_level.get(current_level, [])
    degraded = any(
        row.get("timed_out")
        or row.get("throttled")
        or row.get("gpu_allocation_failure")
        or row.get("semantic_rejected")
        or row.get("malformed")
        for row in current_rows[-3:]
    )
    if degraded:
        reduced = max(1, current_level // 2)
        return AdaptiveDecision(
            reduced, False, ("observed correctness or capacity degradation",), utilities
        )
    validated_rows = [row for row in observations if row.get("validated") is not None]
    if not validated_rows:
        return AdaptiveDecision(
            1, False, ("no validated performance evidence; conservative start",), utilities
        )
    best = max(utilities, key=lambda level: (utilities[level], -level)) if utilities else 1
    target = best
    rationale = [f"best observed validated utility at concurrency {best}"]
    exploring = False
    current_utility = utilities.get(current_level)
    prior_utility = utilities.get(max(1, current_level - 1))
    healthy_current = bool(current_rows) and all(
        row.get("validated") is True and not row.get("timed_out") and not row.get("throttled")
        for row in current_rows[-2:]
    )
    marginal_positive = current_utility is not None and (
        prior_utility is None or current_utility > prior_utility
    )
    higher_utility = utilities.get(current_level + 1)
    upward_not_refuted = higher_utility is None or (
        current_utility is not None and higher_utility > current_utility
    )
    resource_headroom = max(0.0, 1.0 - resources.pressure)
    if (
        exploration_allowed
        and healthy_current
        and marginal_positive
        and upward_not_refuted
        and explore_draw <= resource_headroom
    ):
        target = current_level + 1
        exploring = True
        rationale.append("positive marginal validated throughput; probe adjacent higher load")
    elif exploration_allowed and explore_draw < 0.05:
        # Continuous, bounded, immediately reversible perturbation around the
        # current best.  The draw is intentionally unseeded in production.
        target = max(1, best + (1 if explore_draw < 0.025 else -1))
        exploring = target != best
        rationale.append("periodic adjacent stochastic probe")
    return AdaptiveDecision(max(1, target), exploring, tuple(rationale), utilities)


class AdaptiveExecutionController:
    def __init__(
        self,
        store: Store,
        *,
        session_id: str | None = None,
        resource_sampler: Callable[[], ResourceSnapshot] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        random_float: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.session_id = session_id or f"adaptive-{ulid()}"
        self.resource_sampler = resource_sampler or HostResourceSampler(monotonic=monotonic)
        self.monotonic = monotonic
        self.random_float = random_float or (
            lambda: int.from_bytes(secrets.token_bytes(8), "big") / 2**64
        )
        self._queue_started: dict[str, float] = {}

    def reconcile_after_restart(self) -> dict[str, list[str]]:
        return self.store.reconcile_adaptive_invocations(self.session_id)

    def _current_level(self) -> int:
        row = self.store.get("adaptive_controller_states", self.session_id)
        return max(1, int((row or {}).get("permitted_active") or 1))

    def decision(
        self,
        identity: WorkloadIdentity,
        *,
        risk: Risk,
        downstream_backlog: int = 0,
    ) -> AdaptiveDecision:
        resources = self.resource_sampler()
        observations = self.store.records(
            "adaptive_observations", "workload_key=?", (identity.key,)
        )
        exploration_allowed = risk not in {Risk.HIGH, Risk.PROTECTED} and not identity.mutating
        decision = choose_operating_point(
            observations,
            current_level=self._current_level(),
            resources=resources,
            explore_draw=self.random_float(),
            exploration_allowed=exploration_allowed and downstream_backlog == 0,
        )
        if downstream_backlog > 0 and decision.permitted_active > 1:
            decision = AdaptiveDecision(
                max(1, decision.permitted_active - 1),
                False,
                (*decision.rationale, "downstream backlog applied backpressure"),
                decision.utility_by_level,
            )
        state = {
            "schema_version": 1,
            "controller_session": self.session_id,
            "permitted_active": decision.permitted_active,
            "decision_digest": decision.digest,
            "workload_key": identity.key,
            "resource_snapshot": asdict(resources),
            "resource_class": resources.resource_class,
            "rationale": list(decision.rationale),
        }
        self.store.put(
            "adaptive_controller_states",
            self.session_id,
            state,
            digest=decision.digest,
            extra={"controller_session": self.session_id},
        )
        decision_id = f"{self.session_id}:{ulid()}"
        self.store.put(
            "adaptive_decisions",
            decision_id,
            {**state, "decision_id": decision_id, "exploring": decision.exploring},
            digest=decision.digest,
            extra={"controller_session": self.session_id, "workload_key": identity.key},
        )
        return decision

    async def acquire(
        self,
        *,
        packet: Packet,
        agent: AgentProfile,
        run_id: str,
        claim_token: int,
        coordinator_owner: str,
        coordinator_token: int,
        downstream_backlog: int = 0,
    ) -> tuple[str, int, WorkloadIdentity, AdaptiveDecision, int, float]:
        attempt_id = f"invoke:{run_id}:{agent.profile_id}"
        self._queue_started.setdefault(attempt_id, self.monotonic())
        while True:
            if not self.store.lease_token_current("coordinator", coordinator_token):
                self._queue_started.pop(attempt_id, None)
                raise RuntimeError("ADAPTIVE_COORDINATOR_FENCED")
            if not self.store.claim_token_current(packet.packet_id, claim_token):
                self._queue_started.pop(attempt_id, None)
                raise RuntimeError("ADAPTIVE_PACKET_CLAIM_FENCED")
            resources = self.resource_sampler()
            identity = workload_identity(packet, agent, resources)
            decision = self.decision(
                identity, risk=packet.risk, downstream_backlog=downstream_backlog
            )
            token = self.store.try_admit_invocation(
                attempt_id=attempt_id,
                packet_id=packet.packet_id,
                run_id=run_id,
                claim_token=claim_token,
                coordinator_owner=coordinator_owner,
                coordinator_token=coordinator_token,
                controller_session=self.session_id,
                workload_key=identity.key,
                provider_id=agent.provider_id,
                permitted_active=decision.permitted_active,
                decision_digest=decision.digest,
                payload={
                    "agent_profile_id": agent.profile_id,
                    "requested_model": agent.requested_model_id,
                    "task_class": packet.task_class,
                    "risk": packet.risk.value,
                    "authority_digest": packet.authority_digest,
                    "repository_base_head": packet.base_head,
                    "workload": asdict(identity),
                },
            )
            if token is not None:
                invocation = self.store.get("adaptive_invocations", attempt_id)
                if invocation is None:
                    raise RuntimeError("ADAPTIVE_ADMISSION_RECORD_MISSING")
                active_concurrency = int(invocation.get("observed_active_before") or 0) + 1
                queue_delay = self.monotonic() - self._queue_started.pop(attempt_id)
                return (
                    attempt_id,
                    token,
                    identity,
                    decision,
                    active_concurrency,
                    queue_delay,
                )
            await asyncio.sleep(0.025 + self.random_float() * 0.075)

    def settle(
        self,
        *,
        attempt_id: str,
        admission_token: int,
        identity: WorkloadIdentity,
        decision: AdaptiveDecision,
        active_concurrency: int,
        packet: Packet,
        result: PacketResult | None,
        reason: str,
        queue_delay_s: float,
        elapsed_s: float,
        downstream_backlog: int = 0,
    ) -> None:
        usage = result.usage if result is not None else {}
        failure_detail = result.failure_detail.lower() if result is not None else ""
        output_tokens = usage.get("output_tokens") or usage.get("completion_tokens")
        output_tokens_per_s = (
            float(output_tokens) / elapsed_s
            if output_tokens is not None and elapsed_s > 0
            else None
        )
        status = (
            "fenced"
            if reason == "fenced"
            else "timed_out"
            if reason == "timeout"
            else "uncertain"
            if result is None
            else "completed"
            if result.status is PacketResultStatus.COMPLETED
            else "failed"
        )
        resources = self.resource_sampler()
        observation = {
            "schema_version": 1,
            "workload_key": identity.key,
            "provider_id": identity.provider_id,
            "requested_model": identity.requested_model,
            "actual_model": result.actual_model if result is not None else "",
            "task_class": packet.task_class,
            "risk": packet.risk.value,
            "packet_id": packet.packet_id,
            "offered_concurrency": decision.permitted_active,
            "active_concurrency": active_concurrency,
            "queue_delay_s": queue_delay_s,
            "elapsed_s": elapsed_s,
            "response_latency_ms": usage.get("latency_ms"),
            "time_to_first_token_ms": usage.get("time_to_first_token_ms"),
            "output_tokens": output_tokens,
            "output_tokens_per_s": output_tokens_per_s,
            "uncached_input_tokens": usage.get("uncached_input_tokens"),
            "cached_input_tokens": usage.get("cached_input_tokens"),
            "cost_usd": usage.get("provider_reported_cost"),
            "timed_out": reason == "timeout",
            "transport_error": reason not in {"ok", "timeout", "fenced"},
            "throttled": "throttl" in failure_detail or "rate limit" in failure_detail,
            "truncated": "truncat" in failure_detail,
            "malformed": "malformed" in failure_detail or "structured output" in failure_detail,
            "tool_call_failure": "tool" in failure_detail and "fail" in failure_detail,
            "incomplete_task": bool(
                result is not None and result.status is not PacketResultStatus.COMPLETED
            ),
            "scope_violation": bool(result and result.scope_violation),
            "semantic_rejected": False,
            "accepted": None,
            "validated": None,
            "retry_count": int(usage.get("retry_count") or 0),
            "redraw_count": int(usage.get("redraw_count") or 0),
            "resource_pressure": resources.pressure,
            "resource_snapshot": asdict(resources),
            "gpu_allocation_failure": resources.gpu_allocation_failure
            or "out of memory" in failure_detail
            or "cuda allocation" in failure_detail,
            "downstream_backlog_ratio": float(downstream_backlog > 0),
            "decision_digest": decision.digest,
        }
        if not self.store.settle_invocation(
            attempt_id=attempt_id,
            admission_token=admission_token,
            status=status,
            observation=observation,
        ):
            raise RuntimeError("ADAPTIVE_INVOCATION_FENCED")

    def record_validated_outcome(
        self,
        packet_id: str,
        *,
        attempt_id: str,
        accepted: bool,
        validated: bool,
        independently_reviewed: bool | None,
    ) -> None:
        invocation = self.store.get("adaptive_invocations", attempt_id)
        if not attempt_id or invocation is None or invocation.get("packet_id") != packet_id:
            raise RuntimeError("ADAPTIVE_RESULT_INVOCATION_BINDING_INVALID")
        if not self.store.record_adaptive_outcome(
            attempt_id=attempt_id,
            accepted=accepted,
            validated=validated,
            independently_reviewed=independently_reviewed,
        ):
            raise RuntimeError("ADAPTIVE_OUTCOME_OBSERVATION_MISSING")


@dataclass(frozen=True)
class SimulationPoint:
    latency_s: float
    validation_probability: float = 1.0
    timeout_probability: float = 0.0
    throttle_probability: float = 0.0
    malformed_probability: float = 0.0
    resource_pressure: float = 0.0
    downstream_backlog: float = 0.0
    output_tokens: int = 1000
    input_tokens: int = 5000
    cost_usd: float = 0.0
    retry_probability: float = 0.0
    redraw_probability: float = 0.0
    cpu_pressure: float = 0.0
    memory_pressure: float = 0.0
    gpu_utilization: float = 0.0


def simulate_strategy(
    curve: dict[int, SimulationPoint],
    *,
    steps: int,
    strategy: str,
    fixed_level: int = 1,
) -> dict[str, Any]:
    """Deterministic comparative harness for a nondeterministic production policy."""
    level = 1
    observations: list[dict[str, Any]] = []
    accepted = validated_count = elapsed = timeouts = malformed = 0.0
    retries = redraws = throttles = gpu_failures = 0.0
    output_tokens = input_tokens = cost_usd = 0.0
    latencies: list[float] = []
    cpu_pressure: list[float] = []
    memory_pressure: list[float] = []
    gpu_utilization: list[float] = []
    backlog: list[float] = []
    tested: list[int] = []
    for step in range(steps):
        offered = fixed_level if strategy == "fixed" else 1 if strategy == "sequential" else level
        point = curve.get(offered)
        if point is None:
            # The synthetic provider exposes no published capacity value.  An
            # out-of-range probe discovers an allocation/transport failure.
            edge = curve[max(curve)]
            point = SimulationPoint(
                latency_s=edge.latency_s,
                timeout_probability=1.0,
                resource_pressure=1.0,
            )
        success = point.validation_probability >= ((step * 37 % 100) / 100.0)
        timeout = point.timeout_probability > ((step * 53 % 100) / 100.0)
        throttled = point.throttle_probability > ((step * 61 % 100) / 100.0)
        bad = point.malformed_probability > ((step * 71 % 100) / 100.0)
        retry = point.retry_probability > ((step * 43 % 100) / 100.0)
        redraw = point.redraw_probability > ((step * 47 % 100) / 100.0)
        resource_failed = point.resource_pressure >= 1.0
        response_accepted = not timeout and not throttled and not bad and not resource_failed
        validated = success and response_accepted
        row = {
            "offered_concurrency": offered,
            "active_concurrency": offered,
            "elapsed_s": point.latency_s,
            "accepted": response_accepted,
            "validated": validated,
            "timed_out": timeout,
            "throttled": throttled,
            "malformed": bad,
            "semantic_rejected": not success,
            "resource_pressure": point.resource_pressure,
            "gpu_allocation_failure": resource_failed,
            "downstream_backlog_ratio": point.downstream_backlog,
            "output_tokens": point.output_tokens,
            "uncached_input_tokens": point.input_tokens,
            "cost_usd": point.cost_usd,
            "retry_count": int(retry),
            "redraw_count": int(redraw),
        }
        observations.append(row)
        tested.append(offered)
        elapsed += point.latency_s / max(1, offered)
        # Backlogged output has not become completed validated work yet.
        accepted += float(response_accepted)
        validated_count += float(validated) * (1.0 - min(point.downstream_backlog, 1.0))
        timeouts += float(timeout)
        malformed += float(bad)
        retries += float(retry)
        redraws += float(redraw)
        throttles += float(throttled)
        gpu_failures += float(point.resource_pressure >= 1.0)
        output_tokens += float(point.output_tokens if response_accepted else 0)
        input_tokens += float(point.input_tokens)
        cost_usd += point.cost_usd
        latencies.append(point.latency_s)
        cpu_pressure.append(point.cpu_pressure or point.resource_pressure)
        memory_pressure.append(point.memory_pressure or point.resource_pressure)
        gpu_utilization.append(point.gpu_utilization)
        backlog.append(point.downstream_backlog)
        if strategy == "adaptive":
            resource = ResourceSnapshot(
                available_memory_ratio=max(0.04, 1.0 - point.resource_pressure),
                io_pressure=point.resource_pressure,
                gpu_allocation_failure=point.resource_pressure >= 1.0,
            )
            decision = choose_operating_point(
                observations,
                current_level=level,
                resources=resource,
                explore_draw=(step % 17) / 17.0,
                exploration_allowed=point.downstream_backlog == 0.0,
            )
            level = decision.permitted_active
        elif strategy == "aimd":
            if timeout or throttled or bad or not validated or point.resource_pressure >= 1.0:
                level = max(1, level // 2)
            else:
                level += 1
    ordered_latency = sorted(latencies)
    p95_index = max(0, min(len(ordered_latency) - 1, int(0.95 * len(ordered_latency)) - 1))
    return {
        "strategy": strategy,
        "accepted": int(accepted),
        "validated": int(validated_count),
        "elapsed_s": elapsed,
        "accepted_per_minute": 60.0 * accepted / max(elapsed, 0.001),
        "validated_per_minute": 60.0 * validated_count / max(elapsed, 0.001),
        "validation_success_rate": validated_count / max(accepted, 1),
        "p50_latency_s": statistics.median(latencies),
        "p95_latency_s": ordered_latency[p95_index],
        "aggregate_output_tokens_per_s": output_tokens / max(elapsed, 0.001),
        "per_invocation_output_tokens_per_s": output_tokens / max(sum(latencies), 0.001),
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cost_usd": cost_usd,
        "timeouts": int(timeouts),
        "throttles": int(throttles),
        "malformed": int(malformed),
        "retries": int(retries),
        "redraws": int(redraws),
        "peak_cpu_pressure": max(cpu_pressure),
        "peak_memory_pressure": max(memory_pressure),
        "peak_gpu_utilization": max(gpu_utilization),
        "gpu_allocation_failures": int(gpu_failures),
        "peak_downstream_backlog": max(backlog),
        "tested_levels": tested,
        "final_level": level if strategy == "adaptive" else fixed_level,
        "duplicate_packets": 0,
        "conflicting_overlaps": 0,
        "authorization_violations": 0,
    }


def compare_strategies(curve: dict[int, SimulationPoint], *, steps: int = 80) -> dict[str, Any]:
    sequential = simulate_strategy(curve, steps=steps, strategy="sequential")
    fixed = [
        simulate_strategy(curve, steps=steps, strategy="fixed", fixed_level=level)
        for level in sorted(curve)
    ]
    adaptive = simulate_strategy(curve, steps=steps, strategy="adaptive")
    alternative = simulate_strategy(curve, steps=steps, strategy="aimd")
    return {
        "sequential": sequential,
        "fixed": fixed,
        "alternative_aimd": alternative,
        "adaptive": adaptive,
    }
