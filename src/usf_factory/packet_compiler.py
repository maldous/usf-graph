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
from .enums import RemediationKind, Risk
from .models import (
    ObligationGraph,
    Packet,
    PacketSet,
    RequiredCapabilities,
    SemanticSnapshot,
)

# Baseline read-only tool profile; editing tools added only when permitted.
# These are exactly the broker-implementable tool families (semantic truth is
# read via the snapshot, not by workers, so there is no usf_query tool).
_READ_TOOLS = ["list_paths", "read_file"]
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

    WRITE-SCOPE AUTHORITY (fail closed):

    - **Semantic packets** (obligations WITH semantic subjects): the planner's
      suggested write scope is NEVER authoritative — it is ignored with a
      finding. Writes come ONLY from a snapshot-bound materialisation CONTRACT
      (``materialisation_index.snapshot_bound`` and built at exactly
      ``snapshot.repository_head``), and only for VERIFIED owners; unresolved or
      ambiguous subjects downgrade the packet to read-only. A working-tree or
      stale index contributes read scope + validation only.
    - **Non-semantic packets**: the planner's write scope is honoured only when
      the task class is explicitly marked ``planner_write_scope_allowed`` in the
      operator-maintained task-class config; otherwise it is stripped.
    """
    tc_by_name = task_classes.by_name()
    findings: list[str] = []
    packets: list[Packet] = []

    index_is_contract = bool(
        materialisation_index is not None
        and getattr(materialisation_index, "snapshot_bound", False)
        and getattr(materialisation_index, "source_commit", "") == snapshot.repository_head
    )
    materialisation_digest = (
        getattr(materialisation_index, "source_digest", "") if materialisation_index else ""
    )

    for obl in graph.obligations:
        task = tc_by_name.get(obl.task_class)
        if task is None:
            findings.append(f"obligation {obl.id}: unknown task_class '{obl.task_class}'")
        caps = _required_caps(task)

        read_paths = sorted(set(obl.suggested_read_scope))
        generated_outputs: list[str] = []
        derived_validation: list[str] = []

        if obl.semantic_subjects:
            # SEMANTIC packet: planner write scope is never authoritative.
            if obl.suggested_write_scope:
                findings.append(
                    f"obligation {obl.id}: planner-suggested write scope "
                    f"{sorted(set(obl.suggested_write_scope))} IGNORED for a semantic "
                    f"obligation (writes require the materialisation contract)"
                )
            write_paths: list[str] = []
            # Only a SOURCE_CHANGE remediation may take repository write scope,
            # even from a verified materialisation owner (build task §1).
            # VALIDATION_EVIDENCE / PROOF_EVIDENCE / ANALYSIS_ONLY / HUMAN_DECISION
            # remain read-only w.r.t. the governed source they validate.
            authorize_writes = index_is_contract and (
                obl.remediation_kind is RemediationKind.SOURCE_CHANGE
            )
            if index_is_contract and not authorize_writes:
                findings.append(
                    f"obligation {obl.id}: remediation_kind "
                    f"'{obl.remediation_kind.value}' is read-only w.r.t. governed source; "
                    f"no write scope granted (only SOURCE_CHANGE may edit governed source)"
                )
            if materialisation_index is not None:
                scope = materialisation_index.derive_scope(
                    sorted(set(obl.semantic_subjects)), authorize_writes=authorize_writes
                )
                read_paths = sorted(set(read_paths) | set(scope.read_paths))
                generated_outputs = sorted(set(scope.generated_outputs))
                derived_validation = sorted(set(scope.validation_profiles))
                write_paths = sorted(set(scope.write_paths))  # verified owners only
                if not index_is_contract and not scope.write_paths:
                    findings.append(
                        f"obligation {obl.id}: materialisation index is not a "
                        f"snapshot-bound contract; packet compiled read-only"
                    )
                if scope.unresolved:
                    findings.append(
                        f"obligation {obl.id}: unresolved subjects {scope.unresolved} "
                        f"(fail closed: no write scope)"
                    )
                if scope.ambiguous:
                    findings.append(
                        f"obligation {obl.id}: ambiguous subjects {scope.ambiguous} "
                        f"(fail closed: no write scope)"
                    )
            else:
                findings.append(
                    f"obligation {obl.id}: no materialisation index; semantic packet "
                    f"compiled read-only"
                )
        else:
            # NON-SEMANTIC packet: planner write scope only for task classes the
            # operator explicitly approved for it.
            write_paths = sorted(set(obl.suggested_write_scope))
            if write_paths and not (task and task.planner_write_scope_allowed):
                findings.append(
                    f"obligation {obl.id}: task class '{obl.task_class}' is not approved "
                    f"for planner-supplied write scope; stripped {write_paths}"
                )
                write_paths = []

        # Fail-closed remediation guard (build task §1): nothing but a
        # SOURCE_CHANGE may carry repository write scope, regardless of how it was
        # derived (semantic contract owner OR the non-semantic planner path).
        if write_paths and obl.remediation_kind is not RemediationKind.SOURCE_CHANGE:
            findings.append(
                f"obligation {obl.id}: remediation_kind "
                f"'{obl.remediation_kind.value}' is not SOURCE_CHANGE; stripped write "
                f"scope {write_paths} (read-only remediation)"
            )
            write_paths = []

        input_digests: dict[str, str] = {}
        if digest_fn is not None:
            for path in read_paths + write_paths:
                dg = digest_fn(path, snapshot.repository_head)
                if dg:
                    input_digests[path] = dg

        objective = obl.root_cause
        if obl.required_outcomes:
            objective = f"{obl.root_cause} => " + "; ".join(obl.required_outcomes)

        # Validation profile:
        #  * A READ-ONLY packet produces no patch, so there is nothing for the wave
        #    validators to check — acceptance is durable analysis evidence instead.
        #  * A SEMANTIC (subject-bearing) mutating packet is validated by its
        #    authority-derived RDF/SHACL/SPARQL profile (from the materialisation
        #    contract) — never by code-oriented task-class defaults (e.g. pytest),
        #    which do not validate RDF semantics.
        #  * A NON-SEMANTIC mutating packet keeps the task-class code profile.
        if not write_paths:
            validation = []
        elif obl.semantic_subjects:
            validation = sorted(set(derived_validation) | {"syntax-parse"})
        else:
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
            remediation_kind=obl.remediation_kind,
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
            materialisation_digest=materialisation_digest,
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
