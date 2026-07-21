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

    def __init__(self, *, digest="sha256:fakeauthority", triples=1234, graphs=7, unresolved=None):
        self._digest = digest
        self._triples = triples
        self._graphs = graphs
        self._unresolved = unresolved or []

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


@pytest.fixture
def fake_authority_factory():
    def make():
        return FakeAuthority()

    return make
