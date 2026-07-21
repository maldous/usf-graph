"""Deterministic conflict detection and antichain selection (build task §12).

Git-clean does not imply semantically compatible. Two packets may run together
in a wave only when they are dependency-ready AND mutually safe: no dependency
relationship, no write/generated-output overlap, no shared semantic subject, no
authority dependency, and neither requires a human decision.
"""

from __future__ import annotations

from .enums import UNSAFE_CONFLICTS, ConflictClass
from .models import ConflictEdge, Packet


def _overlap(a: list[str], b: list[str]) -> set[str]:
    return set(a) & set(b)


def classify_conflict(a: Packet, b: Packet) -> tuple[ConflictClass, str]:
    """Classify the relationship between two packets (most severe first)."""
    if a.human_decision_required or b.human_decision_required:
        return ConflictClass.HUMAN_DECISION_REQUIRED, "one packet requires a human decision"

    w = _overlap(a.write_paths, b.write_paths)
    if w:
        return ConflictClass.WRITE_OVERLAP, f"shared write paths: {sorted(w)}"

    g = _overlap(a.generated_outputs, b.generated_outputs)
    if g:
        return ConflictClass.GENERATED_OUTPUT_OVERLAP, f"shared generated outputs: {sorted(g)}"

    s = _overlap(a.semantic_subjects, b.semantic_subjects)
    if s:
        return ConflictClass.SEMANTIC_OVERLAP, f"shared semantic subjects: {sorted(s)}"

    # Authority dependency: one packet writes a path the other reads.
    ad = _overlap(a.write_paths, b.read_paths) | _overlap(b.write_paths, a.read_paths)
    if ad:
        return ConflictClass.AUTHORITY_DEPENDENT, f"write/read authority dependency: {sorted(ad)}"

    r = _overlap(a.read_paths, b.read_paths)
    if r:
        return ConflictClass.READ_OVERLAP, f"shared read paths: {sorted(r)}"

    return ConflictClass.DISJOINT, "no overlap"


def build_conflict_edges(packets: list[Packet]) -> list[ConflictEdge]:
    """All pairwise conflict edges (both safe and unsafe, for auditability)."""
    edges: list[ConflictEdge] = []
    ordered = sorted(packets, key=lambda p: p.packet_id)
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            a, b = ordered[i], ordered[j]
            cls, reason = classify_conflict(a, b)
            if cls is ConflictClass.DISJOINT:
                continue
            edges.append(
                ConflictEdge(
                    packet_a=a.packet_id, packet_b=b.packet_id, conflict_class=cls, reason=reason
                )
            )
    return edges


def _dependency_ready(packet: Packet, all_ids: set[str]) -> bool:
    """A packet is ready when none of its dependencies are still open in this
    obligation set. Dependencies present in the current set must be resolved by a
    prior integrated wave first (we never pre-plan later waves)."""
    return not (set(packet.dependencies) & all_ids)


def select_antichain(
    packets: list[Packet], edges: list[ConflictEdge]
) -> tuple[list[str], list[str]]:
    """Select the first eligible antichain: dependency-ready, mutually safe.

    Deterministic min-conflict-degree greedy: among dependency-ready packets,
    candidates are considered in order of (fewest unsafe conflicts with other
    ready packets, then ``packet_id``) and added if they have no UNSAFE conflict
    with any already-selected packet. Min-degree ordering tends toward a larger
    antichain than naive id-order while remaining fully deterministic.

    Returns (selected_ids, deferred_ids).
    """
    all_obl_ids = {p.obligation_id for p in packets}

    unsafe: set[frozenset[str]] = {
        frozenset({e.packet_a, e.packet_b}) for e in edges if e.conflict_class in UNSAFE_CONFLICTS
    }

    ready = [p for p in packets if _dependency_ready(p, all_obl_ids)]
    not_ready = [p.packet_id for p in packets if not _dependency_ready(p, all_obl_ids)]
    ready_ids = {p.packet_id for p in ready}

    # Unsafe-conflict degree of each ready packet, counting only other READY packets.
    degree: dict[str, int] = {p.packet_id: 0 for p in ready}
    for pair in unsafe:
        a, b = tuple(pair)
        if a in ready_ids and b in ready_ids:
            degree[a] += 1
            degree[b] += 1

    ordered = sorted(ready, key=lambda p: (degree[p.packet_id], p.packet_id))

    selected: list[str] = []
    deferred: list[str] = list(not_ready)
    for pkt in ordered:
        if any(frozenset({pkt.packet_id, s}) in unsafe for s in selected):
            deferred.append(pkt.packet_id)
        else:
            selected.append(pkt.packet_id)
    return sorted(selected), sorted(deferred)
