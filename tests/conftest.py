"""Shared test fixtures.

Everything here is hermetic: a temporary git repo stands in for /usf, a fake
authority client stands in for the USF MCP server, and all factory state lives in
per-test temp directories. No test touches the real /usf, /root/.env, or network.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from usf_factory.authority import READ_ONLY_TOOLS, ToolCallResult
from usf_factory.context import build_context


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture(autouse=True)
def _isolate_factory_paths(tmp_path_factory, monkeypatch):
    """Every test uses temp factory dirs (never the real /root/.local paths), so
    the suite passes as a non-root CI user. Per-test fixtures may re-point them."""
    base = tmp_path_factory.mktemp("factory-xdg")
    monkeypatch.setenv("USF_FACTORY_SHARE", str(base / "share"))
    monkeypatch.setenv("USF_FACTORY_STATE", str(base / "state"))
    monkeypatch.setenv("USF_FACTORY_CACHE", str(base / "cache"))
    monkeypatch.setenv("USF_FACTORY_CONFIG", str(base / "config"))


@pytest.fixture
def tmp_usf(tmp_path: Path) -> Path:
    """A temporary git repo standing in for /usf, with fixture-relevant files."""
    repo = tmp_path / "usf"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "test@example.com"], repo)
    _git(["config", "user.name", "test"], repo)
    (repo / "GOAL.md").write_text("# GOAL\ndeliver USF\n", encoding="utf-8")
    (repo / "semantic").mkdir()
    (repo / "semantic" / "ontology.ttl").write_text("# ontology\n", encoding="utf-8")
    (repo / "semantic" / "shapes").mkdir()
    (repo / "semantic" / "shapes" / "lifecycle.ttl").write_text("# lifecycle\n", encoding="utf-8")
    (repo / "semantic" / "queries").mkdir()
    (repo / "semantic" / "queries" / ".keep").write_text("", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "init"], repo)
    return repo


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    """A conforming temp env file with a couple of fake (non-real) values."""
    p = tmp_path / "dot.env"
    p.write_text(
        "OPENAI_API_KEY=sk-test-not-real-value-000000\nGROQ_API_KEY=gsk_testnotrealvalue00000\n",
        encoding="utf-8",
    )
    p.chmod(0o600)
    return p


@pytest.fixture
def factory_paths(tmp_path, monkeypatch):
    """Point all XDG-style factory dirs at temp locations."""
    share = tmp_path / "share"
    monkeypatch.setenv("USF_FACTORY_SHARE", str(share))
    monkeypatch.setenv("USF_FACTORY_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("USF_FACTORY_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("USF_FACTORY_CONFIG", str(tmp_path / "config"))
    return share


@pytest.fixture
def ctx(factory_paths, tmp_usf, env_file):
    """A fully isolated RuntimeContext."""
    c = build_context(env_file=env_file, usf_repo=tmp_usf)
    yield c
    c.close()


class FakeAuthority:
    """A minimal stand-in for UsfAuthorityClient (read-only)."""

    def __init__(
        self,
        *,
        digest="sha256:fakeauthority",
        triples=1234,
        graphs=7,
        unresolved=None,
        work_plan_items=None,
    ):
        self._digest = digest
        self._triples = triples
        self._graphs = graphs
        self._unresolved = unresolved or []
        self._work_plan_items = work_plan_items or []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def start(self):
        return None

    def close(self):
        return None

    def list_tools(self):
        return list(READ_ONLY_TOOLS)

    def list_resources(self):
        return []

    def _tcr(self, obj):
        return ToolCallResult(ok=True, content=[{"type": "text", "text": json.dumps(obj)}])

    def health(self):
        return self._tcr({"ok": True, "database": "USF", "triples": self._triples})

    def bootstrap(self, arguments=None):
        return self._tcr(
            {
                "authority": {
                    "digest": self._digest,
                    "triples": self._triples,
                    "coveredGraphCount": self._graphs,
                },
                "openGaps": [{"id": o} for o in self._unresolved],
                "proofObligations": [],
                "validationObligations": [],
                "evidenceResults": [],
                "task": None,
            }
        )

    def work_plan(self, arguments=None):
        offset = int((arguments or {}).get("offset", 0))
        page = self._work_plan_items[offset : offset + 50]
        truncated = offset + 50 < len(self._work_plan_items)
        return self._tcr(
            {
                "schemaVersion": 1,
                "authorityDigest": self._digest,
                "contract": "urn:usf:semanticcontract:test",
                "offset": offset,
                "pageSize": 50,
                "truncated": truncated,
                "nextOffset": offset + 50 if truncated else None,
                "gaps": page,
            }
        )


@pytest.fixture
def fake_authority_factory():
    def make():
        return FakeAuthority()

    return make


def seed_agent(
    store,
    *,
    roles,
    scores,
    provider_id="test-provider",
    model="test-model",
    adapter="ollama",
    actual_models=None,
):
    """Persist an agent profile + an IMMUTABLE qualification run + an admission
    decision so the scheduler can route to it (the production candidate path)."""
    from usf_factory.enums import AuthMode
    from usf_factory.ids import ulid
    from usf_factory.models import AdmissionDecision, AgentProfile, QualificationRun

    far_future = "2999-01-01T00:00:00Z"
    profile = AgentProfile(
        provider_id=provider_id, requested_model_id=model, adapter=adapter, auth_mode=AuthMode.LOCAL
    )
    store.put("agent_profiles", profile.profile_id, profile.content_dict())
    run = QualificationRun(
        run_id=f"qual-{ulid()}",
        agent_profile_id=profile.profile_id,
        suite_id="test",
        suite_version="v1",
        config_digest=profile.digest(),
        dimension_scores=dict(scores),
        actual_models=list(actual_models or []),
        roles_admitted=list(roles),
        expires_at=far_future,
    )
    store.put(
        "qualification_runs",
        run.run_id,
        run.model_dump(mode="json"),
        extra={"agent_profile_id": profile.profile_id, "expires_at": far_future},
    )
    decision = AdmissionDecision(
        decision_id=f"adm-{ulid()}",
        agent_profile_id=profile.profile_id,
        qualification_run_id=run.run_id,
        roles=list(roles),
        method="evidence",
        config_digest=profile.digest(),
        expires_at=far_future,
        decided_at="2000-01-01T00:00:00Z",  # early, so real later decisions win
    )
    store.put(
        "admission_decisions",
        decision.decision_id,
        decision.model_dump(mode="json"),
        extra={"agent_profile_id": profile.profile_id, "qualification_run_id": run.run_id},
    )
    return profile


def all_dimension_scores(value=0.95):
    from usf_factory.enums import SCORE_DIMENSIONS

    return dict.fromkeys(SCORE_DIMENSIONS, value)
