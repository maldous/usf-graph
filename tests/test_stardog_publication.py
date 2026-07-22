"""Real adapter contract against the current usf-graph publication CLI schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from usf_factory.github_delivery import CommandResult, GitHubDelivery
from usf_factory.stardog_publication import StardogPublisher

DIGEST = "sha256:" + "a" * 64
POST_DIGEST = "sha256:" + "b" * 64


class _ToolResult:
    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


class _Authority:
    def __init__(self):
        self.entered = False
        self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_exc):
        self.closed = True

    def health(self):
        assert self.entered
        return _ToolResult({"database": "USF", "ok": True})

    def bootstrap(self):
        assert self.entered
        return _ToolResult({"authority": {"digest": DIGEST}})

    def work_plan(self):
        assert self.entered
        return _ToolResult({"gaps": []})


class _Runner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def run(self, args, *, cwd=None, env=None, timeout=600.0):
        self.calls.append((list(args), cwd, env, timeout))
        output = self.outputs.pop(0)
        return CommandResult(True, 0, json.dumps(output) + "\n", "")


def _validate_result(**over):
    data = {
        "mode": "validate",
        "ok": True,
        "commitOutcome": {
            "state": "validated-rolled-back",
            "exactCandidateStateVerified": True,
            "candidateDigest": "sha256:" + "c" * 64,
            "candidateGraphs": ["urn:usf:graph:one"],
        },
        "contaminationCount": 0,
        "evaluatedAuthorityDigest": DIGEST,
        "postAuthorityDigest": DIGEST,
    }
    data.update(over)
    return data


def _commit_result(**over):
    data = {
        "mode": "commit",
        "ok": True,
        "commitOutcome": {
            "state": "confirmed-response",
            "exactCandidateStateVerified": True,
            "candidateDigest": "sha256:" + "c" * 64,
        },
        "contaminationCount": 0,
        "evaluatedAuthorityDigest": DIGEST,
        "postAuthorityDigest": POST_DIGEST,
        "graphsCleared": 10,
        "authoredLoaded": 8,
        "shapesLoaded": 2,
    }
    data.update(over)
    return data


@pytest.mark.contract
def test_authority_client_is_started_and_closed(ctx):
    clients = []

    def factory():
        client = _Authority()
        clients.append(client)
        return client

    publisher = StardogPublisher(ctx, authority_factory=factory)
    assert publisher.read_authority_binding() == (DIGEST, "USF")
    snapshot = publisher.resnapshot()
    assert snapshot["health"]["ok"] is True
    assert len(clients) == 2 and all(c.entered and c.closed for c in clients)


@pytest.mark.contract
def test_publication_passes_exact_digest_and_parses_current_schema(ctx, tmp_path: Path):
    runner = _Runner([_validate_result(), _commit_result()])
    publisher = StardogPublisher(
        ctx,
        runner=runner,
        credential_env_file=tmp_path / "authority.env",
    )
    validate = publisher.validate_and_rollback(tmp_path, DIGEST)
    commit = publisher.publish_committed(tmp_path, DIGEST)
    assert validate.ok and commit.ok
    assert commit.data["postAuthorityDigest"] == POST_DIGEST
    for args, *_rest in runner.calls:
        assert f"--authority-digest={DIGEST}" in args
        assert args[:2] == ["bash", "-lc"]


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "bad",
    [
        _validate_result(contaminationCount=None),
        _validate_result(postAuthorityDigest=POST_DIGEST),
        _validate_result(commitOutcome={"state": "confirmed-response"}),
        {"ok": True, "postDigest": DIGEST, "contamination": 0},
    ],
)
def test_validate_and_rollback_rejects_missing_or_legacy_fields(ctx, tmp_path: Path, bad):
    publisher = StardogPublisher(ctx, runner=_Runner([bad]))
    assert publisher.validate_and_rollback(tmp_path, DIGEST).ok is False


@pytest.mark.adversarial
def test_committed_publish_rejects_unreconciled_outcome(ctx, tmp_path: Path):
    bad = _commit_result(
        commitOutcome={
            "state": "reconciled-committed",
            "exactCandidateStateVerified": True,
            "transactionClosedVerified": True,
            "candidateDigest": "sha256:" + "c" * 64,
            "observedDigest": "sha256:" + "d" * 64,
        }
    )
    publisher = StardogPublisher(ctx, runner=_Runner([bad]))
    assert publisher.publish_committed(tmp_path, DIGEST).ok is False


@pytest.mark.contract
def test_drift_consumes_mismatched_array_fail_closed(ctx, tmp_path: Path):
    runner = _Runner(
        [
            {"command": "drift", "ok": True, "graphCount": 5, "mismatched": []},
            {"command": "drift", "ok": False, "graphCount": 5, "mismatched": ["g"]},
            {"command": "drift", "ok": True, "mismatches": 0},
        ]
    )
    publisher = StardogPublisher(ctx, runner=runner)
    assert publisher.drift(tmp_path).ok is True
    assert publisher.drift(tmp_path).ok is False
    assert publisher.drift(tmp_path).ok is False


@pytest.mark.adversarial
def test_invalid_authority_digest_is_rejected_before_subprocess(ctx, tmp_path: Path):
    runner = _Runner([])
    publisher = StardogPublisher(ctx, runner=runner)
    with pytest.raises(ValueError, match="exact sha256 digest"):
        publisher.validate_and_rollback(tmp_path, "not-a-digest")
    assert runner.calls == []


@pytest.mark.adversarial
def test_coordinator_subprocess_environments_exclude_unrelated_secrets(ctx, monkeypatch):
    monkeypatch.setenv("UNRELATED_PRIVATE_TOKEN", "must-not-propagate")
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "github-only")
    github = GitHubDelivery(origin_url="https://github.com/maldous/usf-graph.git")
    publisher = StardogPublisher(ctx)
    assert "UNRELATED_PRIVATE_TOKEN" not in github.env
    assert "UNRELATED_PRIVATE_TOKEN" not in publisher.env
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in github.env
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in publisher.env
