"""Phases 8-9: semantic-delta extraction, review context bundle (actual patch +
provider fields), and the AI integrator."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.integration import SemanticAiIntegrator
from usf_factory.models import AgentResponse, Attribution, PacketResult
from usf_factory.review import AiReviewer, ReviewContextBundle
from usf_factory.semantic_delta import extract_semantic_delta

# ---- Phase 9: semantic delta from the PATCH (not worker claims) ------------ #

_TTL_PATCH = """--- a/semantic/ontology.ttl
+++ b/semantic/ontology.ttl
@@ -1,3 +1,4 @@
 @prefix ex: <https://ex/ns#> .
 ex:Widget a ex:Class .
-ex:Old a ex:Class .
+ex:New a ex:Class .
"""

_PY_PATCH = """--- a/gen/thing.py
+++ b/gen/thing.py
@@ -0,0 +1,2 @@
+def new_symbol():
+    return 1
"""


@pytest.mark.unit
def test_semantic_delta_from_turtle_patch():
    d = extract_semantic_delta(_TTL_PATCH)
    assert "https://ex/ns#New" in d.iris_added
    assert "https://ex/ns#Old" in d.iris_removed
    # Widget is a context line (unchanged) — not added/removed.
    assert "https://ex/ns#Widget" not in d.iris_added
    assert "https://ex/ns#Widget" not in d.iris_removed
    assert d.changed_paths == ["semantic/ontology.ttl"]


@pytest.mark.unit
def test_semantic_delta_captures_runtime_symbols():
    d = extract_semantic_delta(_PY_PATCH)
    assert "gen/thing.py:new_symbol" in d.runtime_symbols_changed
    assert d.iris_added == []  # no RDF change


@pytest.mark.unit
def test_semantic_delta_shape_target_change():
    patch = """--- a/semantic/shapes/s.shacl.ttl
+++ b/semantic/shapes/s.shacl.ttl
@@ -1,2 +1,2 @@
 @prefix ex: <https://ex/ns#> .
-ex:S a ex:NodeShape ; ex:targetClass ex:A .
+ex:S a ex:NodeShape ; ex:targetClass ex:B .
"""
    d = extract_semantic_delta(patch)
    assert (
        "https://ex/ns#B" in d.shape_targets_changed or "https://ex/ns#A" in d.shape_targets_changed
    )


# ---- Phase 8: review context bundle carries the ACTUAL patch + provider ----- #


@pytest.mark.contract
def test_reviewer_receives_actual_patch_and_provider_fields():
    seen = {}

    async def invoke(req):
        seen["provider"] = req.provider_id
        seen["model"] = req.requested_model_id
        seen["adapter"] = req.adapter_id
        seen["instructions"] = req.instructions
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            output_text='{"approved": true, "findings": [], "risk_flags": []}',
        )

    reviewer = AiReviewer(
        invoke, "agent-rev", provider_id="ollama", model_id="m", adapter_id="ollama"
    )
    bundle = ReviewContextBundle(
        set_id="s1",
        effective_diff=_TTL_PATCH,
        semantic_delta=extract_semantic_delta(_TTL_PATCH).to_dict(),
        validation_gates={"format": True, "unit-tests": True},
    )
    review = asyncio.run(reviewer.review("s1", None, bundle))
    assert review.approved is True
    # Explicit provider/model/adapter routing on the request.
    assert seen["provider"] == "ollama" and seen["model"] == "m" and seen["adapter"] == "ollama"
    # The ACTUAL diff + validation evidence are in the prompt (not just an id).
    assert "ex:New" in seen["instructions"]
    assert "validationGates" in seen["instructions"]


@pytest.mark.adversarial
def test_reviewer_unparseable_output_withholds_approval():
    async def invoke(req):
        return AgentResponse(agent_profile_id=req.agent_profile_id, output_text="not json")

    reviewer = AiReviewer(invoke, "agent-rev", provider_id="ollama", model_id="m")
    review = asyncio.run(reviewer.review("s1", None, ReviewContextBundle(set_id="s1")))
    assert review.approved is False


# ---- Phase 9: AI integrator reconciles a fixture conflict ------------------ #


@pytest.mark.contract
def test_ai_integrator_resolves_fixture_conflict():
    reconciled = """--- a/semantic/ontology.ttl
+++ b/semantic/ontology.ttl
@@ -1,2 +1,3 @@
 @prefix ex: <https://ex/ns#> .
+ex:Merged a ex:Class .
"""

    async def invoke(req):
        assert "CONFLICTS" in req.instructions  # integrator got the conflict context
        return AgentResponse(agent_profile_id=req.agent_profile_id, output_text=reconciled)

    integ = SemanticAiIntegrator(invoke, "agent-int", provider_id="ollama", model_id="m")
    results = [
        PacketResult(packet_id="p1", status="COMPLETED", agent_profile_id="a", patch_digest="d1"),
        PacketResult(packet_id="p2", status="COMPLETED", agent_profile_id="b", patch_digest="d2"),
    ]
    patches = {"p1": "--- a/x\n+++ b/x\n@@\n+ex:A\n", "p2": "--- a/x\n+++ b/x\n@@\n+ex:B\n"}
    effective, attrs = asyncio.run(integ.integrate(results, ["subject overlap p1/p2"], patches))
    assert "ex:Merged" in effective
    # Attribution preserved for every worker packet.
    assert set(attrs) == {"p1", "p2"}
    assert all(isinstance(a, Attribution) for a in attrs.values())
