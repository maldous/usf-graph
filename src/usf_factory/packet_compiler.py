"""Deterministic packet compiler (DESIGN Phase 6 / build task §12).

The compiler — NOT the planner — decides executable packets. It maps the
obligation graph onto content-addressed packets bound to a snapshot, computes
read/write scopes, freezes input digests, sets required capabilities and
validation, builds the conflict graph, and selects the first eligible antichain.
"""

from __future__ import annotations

from collections.abc import Callable

from .clock import utc_now_iso
from .config import TaskClassConfig, TaskClassDef
from .conflict_graph import build_conflict_edges, select_antichain
from .enums import Risk
from .models import (
    ObligationGraph,
    Packet,
    PacketSet,
    RequiredCapabilities,
    SemanticSnapshot,
)

# Baseline read-only tool profile; editing tools added only when permitted.
_READ_TOOLS = ["usf_query", "read_file", "list_paths"]
_EDIT_TOOLS = ["edit_file", "write_patch", "run_focused_tests"]

DigestFn = Callable[[str, str], str | None]  # (path, base_head) -> digest|None


def _required_caps(task: TaskClassDef | None) -> RequiredCapabilities:
    rc = (task.required_capabilities if task else {}) or {}
    return RequiredCapabilities(
        semantic_reasoning=float(rc.get("semantic_reasoning", 0.0)),
        rdf_owl=float(rc.get("rdf_owl", 0.0)),
        shacl_sparql=float(rc.get("shacl_sparql", 0.0)),
        structured_output=float(rc.get("structured_output", 0.8)),
        repository_editing=bool(rc.get("repository_editing", False)),
        min_context_tokens=int(rc.get("min_context_tokens", 8000)),
    )


def _permitted_tools(task: TaskClassDef | None, caps: RequiredCapabilities) -> list[str]:
    tools = list(_READ_TOOLS)
    if caps.repository_editing:
        tools += _EDIT_TOOLS
    return sorted(set(tools))


def _within_limits(packet: Packet, task: TaskClassDef | None) -> bool:
    if task is None:
        return True
    return (
        len(packet.write_paths) <= task.max_files
        and len(packet.semantic_subjects) <= task.max_semantic_subjects
    )


def compile_packets(
    graph: ObligationGraph,
    snapshot: SemanticSnapshot,
    task_classes: TaskClassConfig,
    *,
    digest_fn: DigestFn | None = None,
    materialisation_index=None,
) -> tuple[PacketSet, list[str]]:
    """Compile an obligation graph into a frozen packet set + compiler findings.

    When ``materialisation_index`` is provided, read/write scope, generated
    outputs and validation profiles are derived DETERMINISTICALLY from it (the
    planner's suggested paths are not authoritative). Subjects that are unresolved
    or ambiguous fail closed: the packet is downgraded to read-only (a
    mapping-resolution packet), never given a write scope.
    """
    tc_by_name = task_classes.by_name()
    findings: list[str] = []
    packets: list[Packet] = []

    for obl in graph.obligations:
        task = tc_by_name.get(obl.task_class)
        if task is None:
            findings.append(f"obligation {obl.id}: unknown task_class '{obl.task_class}'")
        caps = _required_caps(task)

        read_paths = sorted(set(obl.suggested_read_scope))
        write_paths = sorted(set(obl.suggested_write_scope))
        generated_outputs: list[str] = []
        derived_validation: list[str] = []

        if materialisation_index is not None and obl.semantic_subjects:
            # The index is QUARANTINED (analysis-only): it enriches READ scope,
            # generated outputs and validation profiles but never authorizes a
            # write scope. Writes remain from the explicit obligation scope.
            scope = materialisation_index.derive_scope(sorted(set(obl.semantic_subjects)))
            read_paths = sorted(set(read_paths) | set(scope.read_paths))
            generated_outputs = sorted(set(scope.generated_outputs))
            derived_validation = sorted(set(scope.validation_profiles))
            if scope.unresolved:
                findings.append(
                    f"obligation {obl.id}: unresolved subjects {scope.unresolved} "
                    f"(index is analysis-only; not used to authorize writes)"
                )
            if scope.ambiguous:
                findings.append(
                    f"obligation {obl.id}: ambiguous subjects {scope.ambiguous} "
                    f"(index is analysis-only; not used to authorize writes)"
                )

        input_digests: dict[str, str] = {}
        if digest_fn is not None:
            for path in read_paths + write_paths:
                dg = digest_fn(path, snapshot.repository_head)
                if dg:
                    input_digests[path] = dg

        objective = obl.root_cause
        if obl.required_outcomes:
            objective = f"{obl.root_cause} => " + "; ".join(obl.required_outcomes)

        validation = sorted(
            set((list(task.default_validation) if task else []) + derived_validation)
        )
        packet = Packet(
            obligation_id=obl.id,
            snapshot_id=snapshot.snapshot_id,
            authority_digest=snapshot.authority_digest,
            base_head=snapshot.repository_head,
            objective=objective,
            task_class=obl.task_class,
            risk=obl.risk,
            semantic_subjects=sorted(set(obl.semantic_subjects)),
            read_paths=read_paths,
            write_paths=write_paths,
            generated_outputs=generated_outputs,
            input_digests=input_digests,
            dependencies=sorted(set(obl.dependencies)),
            conflicts_with=[],
            required_capabilities=caps,
            acceptance_criteria=list(obl.acceptance_criteria),
            required_validation=validation,
            permitted_tools=_permitted_tools(task, caps),
            # ANY repository file content in scope (read OR write) is at least
            # private-source — a read-only packet still exposes source through
            # its read scope. Only a packet with no file paths at all (pure
            # semantic identifiers/digests/summaries) is private-metadata.
            data_classification=(
                "private-source" if (write_paths or read_paths) else "private-metadata"
            ),
            human_decision_required=obl.human_decision_required,
        )
        packets.append(packet)

    # Fail-open guards: a packet is only selectable when its task class is known
    # AND it is within limits. Unknown task classes / oversized packets are
    # excluded from execution selection (never silently run).
    selectable: list[Packet] = []
    for p in packets:
        task = tc_by_name.get(p.task_class)
        if task is None:
            findings.append(
                f"packet {p.packet_id} for obligation {p.obligation_id} has unknown "
                f"task_class '{p.task_class}'; excluded from selection"
            )
            continue
        if _within_limits(p, task):
            selectable.append(p)
        else:
            findings.append(
                f"packet {p.packet_id} for obligation {p.obligation_id} exceeds task limits; deferred"
            )

    edges = build_conflict_edges(packets)
    selected, deferred_selectable = select_antichain(selectable, edges)

    selectable_ids = {p.packet_id for p in selectable}
    deferred = sorted(
        set(deferred_selectable)
        | {p.packet_id for p in packets if p.packet_id not in selectable_ids}
    )

    # Record conflict references on packets (deterministic, for auditability).
    conflict_map: dict[str, set[str]] = {}
    for e in edges:
        conflict_map.setdefault(e.packet_a, set()).add(e.packet_b)
        conflict_map.setdefault(e.packet_b, set()).add(e.packet_a)
    packets = [
        p.model_copy(update={"conflicts_with": sorted(conflict_map.get(p.packet_id, set()))})
        for p in packets
    ]

    pset = PacketSet(
        snapshot_id=snapshot.snapshot_id,
        graph_id=graph.graph_id,
        packets=packets,
        selected_packet_ids=sorted(selected),
        deferred_packet_ids=deferred,
        conflicts=edges,
        compiled_at=utc_now_iso(),
    )

    if any(p.risk is Risk.PROTECTED for p in packets):
        findings.append("packet set contains PROTECTED-risk packets; exploration disabled")

    return pset, findings
