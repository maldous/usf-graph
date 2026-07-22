"""S4 bounded context pack + NEEDS_CONTEXT retry; S6 usage propagation + token
routing tie-break."""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest

from usf_factory.enums import AuthMode, PacketResultStatus
from usf_factory.models import AgentProfile, AgentResponse, Packet, TokenUsage


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def mirror(ctx):
    """A factory mirror containing a subject-bearing RDF file + a shape."""
    m = ctx.paths.mirror
    m.parent.mkdir(parents=True, exist_ok=True)
    work = ctx.paths.share / "seed"
    work.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", "-b", "main"], work)
    _git(["config", "user.email", "t@e"], work)
    _git(["config", "user.name", "t"], work)
    (work / "rules").mkdir()
    (work / "rules" / "example.ttl").write_text(
        "@prefix ex: <https://example.org/usf#> .\n"
        "ex:Rule_A1 a ex:ValidationObligation ;\n"
        '  ex:status "OPEN" .\n'
        "ex:Other a ex:Thing .\n"
    )
    _git(["add", "-A"], work)
    _git(["commit", "-q", "-m", "seed"], work)
    subprocess.run(
        ["git", "clone", "--mirror", "--no-hardlinks", "--no-local", str(work), str(m)],
        check=True,
        capture_output=True,
        text=True,
    )
    head = subprocess.run(
        ["git", "-C", str(m), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return head


def _packet(head, subjects=("https://example.org/usf#Rule_A1",), read=("rules/example.ttl",)):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head=head,
        objective="analyze the validation obligation",
        task_class="semantic-planning",
        semantic_subjects=list(subjects),
        read_paths=list(read),
        acceptance_criteria=["bounded analysis"],
        permitted_tools=["read_file"],
    )


# ---- S4: context pack contains authorized subject-specific source only ------- #


@pytest.mark.e2e
def test_context_pack_includes_authorized_subject_excerpt(ctx, mirror):
    from usf_factory.context_pack import build_context_pack

    pack = build_context_pack(ctx, _packet(mirror), egress_allowed=True)
    rendered = pack.render()
    assert "Rule_A1" in rendered  # subject-specific block extracted
    assert "@prefix" in rendered  # prefixes preserved for interpretability
    assert pack.context_pack_digest and pack.stable_prefix_digest and pack.task_delta_digest


@pytest.mark.adversarial
def test_context_pack_withholds_source_when_egress_denied(ctx, mirror):
    from usf_factory.context_pack import build_context_pack

    pack = build_context_pack(
        ctx, _packet(mirror), egress_allowed=False, egress_reason="external-cloud"
    )
    rendered = pack.render()
    assert "SOURCE CONTENT WITHHELD" in rendered  # metadata projection only
    assert 'ex:status "OPEN"' not in rendered  # raw source not leaked
    # Paths + digests are still shared (authorized metadata).
    assert "rules/example.ttl" in rendered


# ---- S6: AiWorker propagates usage into PacketResult ------------------------- #


def _agent():
    return AgentProfile(
        provider_id="claude-cli",
        requested_model_id="claude-opus-4-8",
        adapter="claude_cli",
        auth_mode=AuthMode.OIDC_CLI,
    )


@pytest.mark.e2e
def test_aiworker_propagates_usage(ctx, mirror):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    good = json.dumps({"status": "COMPLETED", "evidence_produced": ["finding: obligation is OPEN"]})

    async def invoke(req):
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            output_text=good,
            actual_provider="claude-cli",
            actual_model="claude-opus-4-8",
            usage=TokenUsage(
                input_tokens=1200,
                cached_input_tokens=800,
                uncached_input_tokens=400,
                output_tokens=90,
                actual_model="claude-opus-4-8",
                actual_model_verified=True,
                provider_reported_cost=0.04,
            ),
        )

    worker = AiWorker(
        invoke,
        isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
        store=ctx.store,
        ctx=ctx,
        source_content_allowed=True,
    )
    result = asyncio.run(worker.execute(_packet(mirror), None, _agent()))
    assert result.status is PacketResultStatus.COMPLETED
    u = result.usage
    assert u["input_tokens"] == 1200 and u["output_tokens"] == 90
    assert u["cached_input_tokens"] == 800 and u["uncached_input_tokens"] == 400
    assert u["actual_model_verified"] is True and u["usage_reported"] is True
    assert u["context_pack_digest"] and u["stable_prefix_digest"] and u["task_delta_digest"]


@pytest.mark.adversarial
def test_aiworker_missing_usage_is_unknown_not_zero(ctx, mirror):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    good = json.dumps({"status": "COMPLETED", "evidence_produced": ["finding"]})

    async def invoke(req):
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            output_text=good,
            actual_provider="p",
            actual_model=None,
        )  # no usage object

    worker = AiWorker(
        invoke,
        isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
        store=ctx.store,
        ctx=ctx,
        source_content_allowed=True,
    )
    result = asyncio.run(worker.execute(_packet(mirror), None, _agent()))
    assert result.usage["input_tokens"] is None  # unknown, NOT zero
    assert result.usage["usage_reported"] is False


# ---- S4: NEEDS_CONTEXT one bounded retry ------------------------------------ #


@pytest.mark.e2e
def test_needs_context_one_bounded_retry(ctx, mirror):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    calls = {"n": 0}

    async def invoke(req):
        calls["n"] += 1
        if calls["n"] == 1:
            body = json.dumps(
                {"status": "NEEDS_CONTEXT", "needs_context": {"path": "rules/example.ttl"}}
            )
        else:
            body = json.dumps({"status": "COMPLETED", "evidence_produced": ["ok"]})
        return AgentResponse(
            agent_profile_id=req.agent_profile_id, output_text=body, actual_provider="p"
        )

    worker = AiWorker(
        invoke,
        isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
        store=ctx.store,
        ctx=ctx,
        source_content_allowed=True,
    )
    result = asyncio.run(worker.execute(_packet(mirror), None, _agent()))
    assert calls["n"] == 2  # exactly one retry
    assert result.status is PacketResultStatus.COMPLETED


@pytest.mark.adversarial
def test_needs_context_unauthorized_path_fails(ctx, mirror):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    async def invoke(req):
        body = json.dumps({"status": "NEEDS_CONTEXT", "needs_context": {"path": "/etc/passwd"}})
        return AgentResponse(
            agent_profile_id=req.agent_profile_id, output_text=body, actual_provider="p"
        )

    worker = AiWorker(
        invoke,
        isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
        store=ctx.store,
        ctx=ctx,
        source_content_allowed=True,
    )
    result = asyncio.run(worker.execute(_packet(mirror), None, _agent()))
    assert result.status is PacketResultStatus.FAILED  # arbitrary path refused


@pytest.mark.adversarial
def test_mutating_packet_without_egress_is_blocked(ctx, mirror):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    async def invoke(req):  # should never be called
        raise AssertionError("must not invoke when egress blocked")

    pkt = _packet(mirror, read=("rules/example.ttl",))
    pkt = pkt.model_copy(
        update={"write_paths": ["rules/example.ttl"], "task_class": "sparql-authoring"}
    )
    worker = AiWorker(
        invoke,
        isolation=RepoIsolation(ctx.paths, ctx.usf_repo),
        store=ctx.store,
        ctx=ctx,
        source_content_allowed=False,
        egress_reason="external-cloud",
    )
    result = asyncio.run(worker.execute(pkt, None, _agent()))
    assert result.status is PacketResultStatus.FAILED
    assert "EGRESS_BLOCKED" in result.failure_detail


# ---- S6: token/cache routing tie-break -------------------------------------- #


@pytest.mark.unit
def test_token_cache_routing_tiebreak(ctx):
    from conftest import all_dimension_scores, seed_agent
    from usf_factory.enums import AdmissionRole
    from usf_factory.roster import _profile_metrics, _rank_key

    # Two equal-qualification analysts; one has better cache reuse + lower uncached.
    hi = seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="p-eff",
        model="m",
        adapter="ollama",
    )
    lo = seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="p-ineff",
        model="m",
        adapter="ollama",
    )
    # Efficient profile: high cache reuse, low uncached; both accepted once.
    for pid, cached, uncached in [(hi.profile_id, 900, 100), (lo.profile_id, 100, 900)]:
        ctx.store.put(
            "profile_metrics",
            f"{pid}:semantic-planning:pk",
            {
                "agent_profile_id": pid,
                "task_class": "semantic-planning",
                "accepted": 1,
                "rejected": 0,
                "cached_input_tokens": cached,
                "uncached_input_tokens": uncached,
                "latency_ms": 10.0,
                "cost_usd": 0.0,
            },
            extra={"agent_profile_id": pid, "task_class": "semantic-planning"},
        )
    run = {"cases_passed": 10, "cases_total": 10, "dimension_scores": all_dimension_scores()}
    key_hi = _rank_key(ctx, hi, run)
    key_lo = _rank_key(ctx, lo, run)
    assert key_hi < key_lo  # better token/cache efficiency ranks first
    assert (
        _profile_metrics(ctx, hi.profile_id)["cache_reuse"]
        > _profile_metrics(ctx, lo.profile_id)["cache_reuse"]
    )
