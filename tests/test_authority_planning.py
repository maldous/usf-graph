"""S1: authority-first planning. The deterministic compiler is authoritative;
the AI optimizer may only rank/consolidate/annotate and can never generate,
invent, alter, or empty the authority obligation set."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.config import load_config
from usf_factory.models import AgentResponse, Obligation, ObligationGraph, SemanticSnapshot
from usf_factory.packet_compiler import compile_packets
from usf_factory.planner import AiPlanOptimizer
from usf_factory.programme_state import ProgrammePlanner, parse_programme_obligations


def _authoritative() -> ObligationGraph:
    return ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="A", root_cause="a", semantic_subjects=["urn:x"], task_class="semantic-planning"
            ),
            Obligation(
                id="B", root_cause="b", semantic_subjects=["urn:y"], task_class="semantic-planning"
            ),
        ],
        planner_profile_id="programme-state-compiler",
    )


def _opt(text: str) -> AiPlanOptimizer:
    async def invoke(req):
        return AgentResponse(agent_profile_id=req.agent_profile_id, output_text=text)

    return AiPlanOptimizer(invoke, "planner-1", task_classes=["semantic-planning"])


# ---- parser extracts live authority work-plan gaps -------------------------- #


@pytest.mark.unit
def test_parse_extracts_work_plan_gaps():
    wp = {
        "gaps": [
            {
                "type": "missing-current-passing-validation",
                "subject": "urn:usf:validationobligation:repositoryexternalartefactmaterialisation",
            }
        ]
    }
    obls = parse_programme_obligations({}, wp)
    assert len(obls) == 1
    assert obls[0]["semantic_subjects"] == [
        "urn:usf:validationobligation:repositoryexternalartefactmaterialisation"
    ]
    # A missing-validation gap maps to a bounded validation-authoring class; its
    # WRITE scope still requires a verified owner (read-only without one).
    assert obls[0]["task_class"] == "sparql-authoring"


# ---- optimizer cannot lose / invent / empty the authority set --------------- #


@pytest.mark.adversarial
def test_optimizer_empty_result_keeps_authoritative():
    graph = _authoritative()
    out = asyncio.run(_opt('{"obligations": []}').optimize(graph))
    assert {o.id for o in out.obligations} == {"A", "B"}  # never emptied


@pytest.mark.adversarial
def test_optimizer_invalid_json_keeps_authoritative():
    graph = _authoritative()
    out = asyncio.run(_opt("not json").optimize(graph))
    assert {o.id for o in out.obligations} == {"A", "B"}


@pytest.mark.adversarial
def test_optimizer_invented_obligation_ignored_authority_preserved():
    graph = _authoritative()
    text = (
        '{"obligations": ['
        '{"id": "A", "root_cause": "a2", "task_class": "semantic-planning"},'
        '{"id": "INVENTED", "root_cause": "z", "task_class": "shacl-repair", '
        '"semantic_subjects": ["urn:evil"], "suggested_write_scope": ["x.ttl"]}]}'
    )
    out = asyncio.run(_opt(text).optimize(graph))
    ids = {o.id for o in out.obligations}
    assert ids == {"A", "B"}  # invented dropped, B (omitted) retained
    a = next(o for o in out.obligations if o.id == "A")
    assert a.semantic_subjects == ["urn:x"]  # subjects never altered
    assert a.task_class == "semantic-planning"  # task_class never altered
    assert a.suggested_write_scope == []  # scope never broadened


@pytest.mark.unit
def test_optimizer_ranks_and_improves_without_altering_identity():
    graph = _authoritative()
    text = (
        '{"obligations": ['
        '{"id": "B", "root_cause": "b", "task_class": "semantic-planning", '
        '"acceptance_criteria": ["clearer criterion"]},'
        '{"id": "A", "root_cause": "a", "task_class": "semantic-planning"}]}'
    )
    out = asyncio.run(_opt(text).optimize(graph))
    assert [o.id for o in out.obligations] == ["B", "A"]  # ranking honored
    b = next(o for o in out.obligations if o.id == "B")
    assert b.acceptance_criteria == ["clearer criterion"]  # improvement accepted
    assert b.semantic_subjects == ["urn:y"]  # identity preserved


@pytest.mark.adversarial
def test_optimizer_deletion_requires_reason():
    graph = _authoritative()
    # Deletion without a reason must NOT drop the authority obligation.
    text = '{"obligations": [{"id": "A", "root_cause": "a", "task_class": "semantic-planning"}], "deletions": [{"id": "B", "reason": ""}]}'
    out = asyncio.run(_opt(text).optimize(graph))
    assert {o.id for o in out.obligations} == {"A", "B"}  # B retained (no reason)


# ---- end-to-end: a non-empty authority plan still compiles packets even when
#      the optimizer returns garbage -------------------------------------------- #


@pytest.mark.e2e
def test_authority_plan_still_compiles_packets_when_optimizer_empty():
    snap = SemanticSnapshot(
        authority_digest="a",
        repository_head="h",
        working_tree_digest="w",
        programme_obligations=[
            {
                "id": "missing-current-passing-validation:urn:usf:vo",
                "root_cause": "authority gap",
                "semantic_subjects": ["urn:usf:vo"],
                "task_class": "semantic-planning",
                "acceptance_criteria": ["bounded analysis"],
                "risk": "low",
            }
        ],
    )
    authoritative = asyncio.run(ProgrammePlanner().plan(snap))
    assert len(authoritative.obligations) == 1
    # Optimizer empties the graph -> engine-level defence keeps authoritative.
    optimized = asyncio.run(_opt('{"obligations": []}').optimize(authoritative))
    assert len(optimized.obligations) == 1  # never zero work
    cfg = load_config()
    pset, _findings = compile_packets(optimized, snap, cfg.task_classes)
    assert len(pset.selected_packet_ids) == 1  # a real packet is produced
