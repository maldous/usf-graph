"""Real adapter contract against the current usf-graph publication CLI schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from usf_factory.github_delivery import CommandResult, GitHubDelivery
from usf_factory.stardog_publication import StardogPublisher

DIGEST = "sha256:" + "a" * 64
RAW_DIGEST = "a" * 64
POST_DIGEST = "sha256:" + "b" * 64


class _ToolResult:
    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


class _Authority:
    def __init__(self, digest=DIGEST):
        self.entered = False
        self.closed = False
        self.digest = digest

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
        return _ToolResult({"authority": {"digest": self.digest}})

    def work_plan(self, arguments=None):
        assert self.entered
        return _ToolResult(
            {
                "schemaVersion": 1,
                "authorityDigest": self.digest
                if self.digest.startswith("sha256:")
                else f"sha256:{self.digest}",
                "gaps": [],
                "truncated": False,
            }
        )


class _Runner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def run(self, args, *, cwd=None, env=None, timeout=600.0):
        self.calls.append((list(args), cwd, env, timeout))
        output = self.outputs.pop(0)
        return CommandResult(True, 0, json.dumps(output) + "\n", "")


class _TextRunner(_Runner):
    def run(self, args, *, cwd=None, env=None, timeout=600.0):
        self.calls.append((list(args), cwd, env, timeout))
        return CommandResult(True, 0, str(self.outputs.pop(0)), "")


class _PagedAuthority(_Authority):
    def __init__(self, gaps, *, move_on_page=False, database="USF"):
        super().__init__()
        self.gaps = gaps
        self.move_on_page = move_on_page
        self.database = database

    def health(self):
        return _ToolResult({"database": self.database, "ok": True})

    def work_plan(self, arguments=None):
        offset = int((arguments or {}).get("offset", 0))
        page = self.gaps[offset : offset + 50]
        digest = "sha256:" + "f" * 64 if self.move_on_page and offset else self.digest
        return _ToolResult(
            {
                "schemaVersion": 1,
                "authorityDigest": digest,
                "offset": offset,
                "pageSize": 50,
                "gaps": page,
                "truncated": offset + 50 < len(self.gaps),
                "nextOffset": offset + 50 if offset + 50 < len(self.gaps) else None,
            }
        )


def _validate_result(**over):
    data = {
        "mode": "validate",
        "ok": True,
        "commitOutcome": {
            "state": "validated-rolled-back",
            "exactCandidateStateVerified": True,
            "candidateDigest": POST_DIGEST,
            "candidateGraphs": ["urn:usf:graph:one"],
        },
        "contaminationCount": 0,
        "graphsCleared": 10,
        "authoredLoaded": 8,
        "shapesLoaded": 2,
        "evaluatedAuthorityDigest": DIGEST,
        "postAuthorityDigest": DIGEST,
        "postTriples": 100,
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
            "candidateDigest": POST_DIGEST,
        },
        "contaminationCount": 0,
        "evaluatedAuthorityDigest": DIGEST,
        "postAuthorityDigest": POST_DIGEST,
        "graphsCleared": 10,
        "authoredLoaded": 8,
        "shapesLoaded": 2,
        "postTriples": 100,
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
def test_authority_binding_canonicalises_live_raw_sha256_witness(ctx):
    publisher = StardogPublisher(ctx, authority_factory=lambda: _Authority(RAW_DIGEST))
    assert publisher.read_authority_binding() == (DIGEST, "USF")


@pytest.mark.contract
def test_publication_passes_exact_digest_and_parses_current_schema(ctx, tmp_path: Path):
    runner = _Runner([_validate_result(), _commit_result()])
    publisher = StardogPublisher(
        ctx,
        runner=runner,
        credential_env_file=tmp_path / "authority.env",
        containment_proven=True,
    )
    validate = publisher.validate_and_rollback(tmp_path, DIGEST)
    commit = publisher.publish_committed(tmp_path, DIGEST, POST_DIGEST)
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
    publisher = StardogPublisher(ctx, runner=_Runner([bad]), containment_proven=True)
    assert publisher.validate_and_rollback(tmp_path, DIGEST).ok is False


@pytest.mark.adversarial
def test_committed_publish_rejects_unreconciled_outcome(ctx, tmp_path: Path):
    bad = _commit_result(
        commitOutcome={
            "state": "reconciled-committed",
            "exactCandidateStateVerified": True,
            "transactionClosedVerified": True,
            "candidateDigest": POST_DIGEST,
            "observedDigest": "sha256:" + "d" * 64,
        }
    )
    publisher = StardogPublisher(ctx, runner=_Runner([bad]), containment_proven=True)
    assert publisher.publish_committed(tmp_path, DIGEST, POST_DIGEST).ok is False


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "text",
    [
        "log prefix\n" + json.dumps(_validate_result()),
        json.dumps(_validate_result()) + "\n" + json.dumps(_validate_result()),
        json.dumps({**_validate_result(), "unexpected": True}),
    ],
)
def test_publication_output_requires_one_exact_json_document(ctx, tmp_path: Path, text):
    publisher = StardogPublisher(
        ctx,
        runner=_TextRunner([text]),
        containment_proven=True,
    )
    assert publisher.validate_and_rollback(tmp_path, DIGEST).ok is False


@pytest.mark.contract
def test_raw_and_tagged_digest_forms_are_canonicalised_at_publication_boundaries(
    ctx, tmp_path: Path
):
    validate = _validate_result(
        evaluatedAuthorityDigest=RAW_DIGEST,
        postAuthorityDigest=RAW_DIGEST,
        commitOutcome={
            "state": "validated-rolled-back",
            "exactCandidateStateVerified": True,
            "candidateDigest": POST_DIGEST.removeprefix("sha256:"),
            "candidateGraphs": ["urn:usf:graph:one"],
        },
    )
    commit = _commit_result(
        evaluatedAuthorityDigest=RAW_DIGEST,
        postAuthorityDigest=POST_DIGEST.removeprefix("sha256:"),
        commitOutcome={
            "state": "confirmed-response",
            "exactCandidateStateVerified": True,
            "candidateDigest": POST_DIGEST.removeprefix("sha256:"),
        },
    )
    publisher = StardogPublisher(ctx, runner=_Runner([validate, commit]), containment_proven=True)
    assert publisher.validate_and_rollback(tmp_path, RAW_DIGEST).ok
    assert publisher.publish_committed(tmp_path, RAW_DIGEST, POST_DIGEST.removeprefix("sha256:")).ok


@pytest.mark.contract
def test_drift_consumes_mismatched_array_fail_closed(ctx, tmp_path: Path):
    runner = _Runner(
        [
            {"command": "drift", "ok": True, "graphCount": 5, "mismatched": []},
            {"command": "drift", "ok": False, "graphCount": 5, "mismatched": ["g"]},
            {"command": "drift", "ok": True, "mismatches": 0},
        ]
    )
    publisher = StardogPublisher(ctx, runner=runner, containment_proven=True)
    assert publisher.drift(tmp_path).ok is True
    assert publisher.drift(tmp_path).ok is False
    assert publisher.drift(tmp_path).ok is False


@pytest.mark.contract
def test_obligation_closure_uses_exact_actionable_identifiers():
    snap = {
        "work_plan": {"schemaVersion": 1, "gaps": [], "truncated": False},
        "bootstrap": {
            "openGaps": [],
            "proofObligations": [{"id": "obl-1"}],
            "history": "previously discussed obl-1",
        },
    }
    assert StardogPublisher.obligation_absent(snap, "missing-proof", "obl-1") is True
    snap["work_plan"]["gaps"] = [{"type": "missing-proof", "subject": "obl-10"}]
    assert StardogPublisher.obligation_absent(snap, "missing-proof", "obl-1") is True
    snap["work_plan"]["gaps"] = [{"subject": "obl-1", "type": "missing-proof"}]
    assert StardogPublisher.obligation_absent(snap, "missing-proof", "obl-1") is False


@pytest.mark.adversarial
def test_obligation_closure_fails_closed_on_truncated_or_malformed_projection():
    assert (
        StardogPublisher.obligation_absent(
            {"work_plan": {"schemaVersion": 1, "gaps": [], "truncated": True}},
            "missing-proof",
            "obl-1",
        )
        is False
    )
    assert StardogPublisher.obligation_absent({"work_plan": {}}, "missing-proof", "obl-1") is False


@pytest.mark.contract
def test_resnapshot_paginates_complete_digest_stable_work_plan(ctx):
    gaps = [{"type": "gap", "subject": f"urn:test:{index:03d}"} for index in range(75)]
    publisher = StardogPublisher(ctx, authority_factory=lambda: _PagedAuthority(gaps))
    snapshot = publisher.resnapshot()
    assert len(snapshot["work_plan"]["gaps"]) == 75
    assert StardogPublisher.obligation_absent(snapshot, "gap", "urn:test:074") is False


@pytest.mark.adversarial
def test_resnapshot_rejects_authority_movement_between_pages(ctx):
    gaps = [{"type": "gap", "subject": f"urn:test:{index:03d}"} for index in range(75)]
    publisher = StardogPublisher(
        ctx, authority_factory=lambda: _PagedAuthority(gaps, move_on_page=True)
    )
    with pytest.raises(ValueError, match="WORK_PLAN_AUTHORITY_MOVED"):
        publisher.resnapshot()


@pytest.mark.adversarial
def test_resnapshot_rejects_duplicate_structured_gap_identity(ctx):
    gaps = [
        {"type": "gap", "subject": "urn:test:duplicate"},
        {"type": "gap", "subject": "urn:test:duplicate"},
    ]
    publisher = StardogPublisher(ctx, authority_factory=lambda: _PagedAuthority(gaps))
    with pytest.raises(ValueError, match="WORK_PLAN_DUPLICATE_GAP_IDENTITY"):
        publisher.resnapshot()


@pytest.mark.adversarial
def test_invalid_authority_digest_is_rejected_before_subprocess(ctx, tmp_path: Path):
    runner = _Runner([])
    publisher = StardogPublisher(ctx, runner=runner, containment_proven=True)
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
