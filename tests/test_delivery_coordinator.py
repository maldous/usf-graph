"""Spec Part B — durable, idempotent delivery coordinator lifecycle.

The GitHub + Stardog boundaries are faked so the REAL coordinator FSM (gating,
idempotent persist-before/after, reconciliation, stale-abort, drift-before-closure)
is exercised end to end without touching a live remote. The same coordinator runs
against real ``git``/``gh``/``npm`` drivers in the live acceptance.
"""

from __future__ import annotations

import pytest

from usf_factory.delivery_coordinator import DeliveryCoordinator, DeliveryInput
from usf_factory.enums import DeliveryState, ProtectedAction, RemediationKind, Risk
from usf_factory.github_delivery import CommandResult
from usf_factory.run_authorization import RunAuthorization
from usf_factory.stardog_publication import PublishStep

FUTURE = "2999-01-01T00:00:00Z"
EXPECTED_DIGEST = "sha256:" + "a" * 64
AFTER_DIGEST = "sha256:" + "b" * 64


def _authz(**over):
    base = dict(
        authorization_id="auth-test",
        issued_at="2000-01-01T00:00:00Z",
        expires_at=FUTURE,
        repositories=["maldous/usf-graph"],
        authority_database="USF",
        permitted_actions=[
            ProtectedAction.PUSH_PR,
            ProtectedAction.MAIN_INTEGRATION,
            ProtectedAction.STARDOG_PUBLICATION,
        ],
        max_pr_merges=10,
        max_authority_publications=10,
    )
    base.update(over)
    return RunAuthorization(**base)


def _authorize(ctx, **over):
    ctx.config.safety.allow_push_pr = True
    ctx.config.safety.allow_main_integration = True
    ctx.config.safety.allow_stardog_publication = True
    ctx.run_authorization = _authz(**over)


class FakeGitHub:
    def __init__(self):
        self.repository_scope = "maldous/usf-graph"
        self.calls: list[str] = []
        self.pushed = 0
        self.merged = 0
        self.head = "reviewedsha000"
        self.fail: set[str] = set()

    def clone_writable(self, dest, base_head):
        self.calls.append("clone")
        return CommandResult("clone" not in self.fail, 0, "", "")

    def apply_effective_diff(self, clone, diff_text, *, patch_path):
        self.calls.append("apply")
        return CommandResult(True, 0, "", "")

    def write_files(self, clone, files):
        self.calls.append("write_files")
        return CommandResult(True, 0, "", "")

    def rederive_diff(self, clone):
        return "diff --git a/x b/x\n+1\n"

    def create_branch(self, clone, branch):
        self.calls.append("branch")
        return CommandResult(True, 0, "", "")

    def commit_with_trailers(self, clone, subject, body, trailers):
        self.calls.append("commit")
        self.trailers = trailers
        return CommandResult(True, 0, self.head, ""), self.head

    def push_branch(self, clone, branch, *, allow_force=False):
        self.calls.append("push")
        self.pushed += 1
        assert allow_force is False  # never force-push
        return CommandResult(
            "push" not in self.fail, 0, "", "" if "push" not in self.fail else "boom"
        )

    def remote_branch_sha(self, clone, branch):
        return CommandResult(True, 0, self.head, ""), self.head

    def open_draft_pr(self, clone, *, base, head, title, body):
        self.calls.append("open_pr")
        return CommandResult(True, 0, "https://gh/pr/7", ""), 7, "https://gh/pr/7"

    def pr_for_head(self, clone, head):
        return CommandResult(True, 0, "", ""), {
            "number": 7,
            "url": "https://gh/pr/7",
            "headRefOid": self.head,
        }

    def mark_ready(self, clone, pr):
        self.calls.append("ready")
        return CommandResult("ready" not in self.fail, 0, "", "")

    def wait_for_checks(self, clone, pr, *, timeout=900.0):
        self.calls.append("checks")
        return CommandResult("checks" not in self.fail, 0, "", "")

    def required_checks(self, clone, pr):
        self.calls.append("required_checks")
        return CommandResult(True, 0, "", ""), [{"name": "verify", "bucket": "pass"}]

    def pr_head_sha(self, clone, pr):
        return self.head

    def merge_pr(self, clone, pr, *, method="squash"):
        self.calls.append("merge")
        self.merged += 1
        return CommandResult("merge" not in self.fail, 0, "", ""), "mergesha111"

    def pr_state(self, clone, pr):
        return {"state": "OPEN", "merged": False, "isDraft": False}


class FakePublisher:
    def __init__(
        self,
        *,
        live_digest=EXPECTED_DIGEST,
        drift_ok=True,
        obligation_gone=True,
        publish_response_lost=False,
    ):
        self.live_digest = live_digest
        self.drift_ok = drift_ok
        self.obligation_gone = obligation_gone
        self.published = 0
        self.publish_response_lost = publish_response_lost

    def read_authority_binding(self):
        return self.live_digest, "USF"

    def install_frozen(self, clone):
        return PublishStep("npm ci", True)

    def run_tests(self, clone):
        return PublishStep("npm test", True)

    def validate_and_rollback(self, clone, expected_authority_digest):
        assert expected_authority_digest == self.live_digest
        return PublishStep(
            "validate",
            True,
            data={
                "contaminationCount": 0,
                "commitOutcome": {"candidateGraphs": ["g1", "g2"]},
            },
        )

    def publish_committed(self, clone, expected_authority_digest):
        assert expected_authority_digest == self.live_digest
        self.published += 1
        self.live_digest = AFTER_DIGEST
        if self.publish_response_lost:
            return PublishStep("publish", False, detail="response lost")
        return PublishStep("publish", True, data={"postAuthorityDigest": AFTER_DIGEST})

    def drift(self, clone):
        return PublishStep("drift", self.drift_ok, data={"mismatches": 0 if self.drift_ok else 3})

    def resnapshot(self):
        return {"work_plan": {"items": [] if self.obligation_gone else [{"id": "obl-1"}]}}

    def obligation_absent(self, snap, obligation_id):
        import json

        return obligation_id not in json.dumps(snap)


def _inp(**over):
    base = dict(
        obligation_id="obl-1",
        set_id="set-1",
        remediation_kind=RemediationKind.SOURCE_CHANGE,
        base_head="basehead000",
        expected_pre_publication_digest=EXPECTED_DIGEST,
        risk=Risk.MEDIUM,
        diff_text="diff --git a/x b/x\n+1\n",
        validation_passed=True,
        review_approved=True,
        reviewer_profile_id="rev-1",
        provider_model_receipts=[{"provider_id": "p", "actual_model": "m"}],
    )
    base.update(over)
    return DeliveryInput(**base)


# --------------------------------------------------------------------------- #


@pytest.mark.e2e
def test_source_change_flows_through_github_and_publication(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.COMPLETE.value
    # The second clone is the fresh checkout at the MERGE commit for publication.
    assert gh.calls == [
        "clone",
        "apply",
        "branch",
        "commit",
        "push",
        "open_pr",
        "ready",
        "checks",
        "required_checks",
        "merge",
        "clone",
    ]
    assert pub.published == 1
    assert rec.merge_commit == "mergesha111"
    assert rec.authority_digest_after == AFTER_DIGEST
    assert rec.graphs_published == ["g1", "g2"]
    # Provenance trailers carry obligation/authority/validation/attribution.
    assert gh.trailers["USF-Obligation"] == "obl-1"
    assert "USF-Model-0" in gh.trailers


@pytest.mark.adversarial
def test_unverified_validation_evidence_cannot_enter_delivery(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(
        _inp(
            remediation_kind=RemediationKind.VALIDATION_EVIDENCE,
            diff_text="diff --git a/x b/x\n+candidate\n",
            authority_evidence_verified=False,
        )
    )
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == "factory validation receipt is not authority-grade evidence"
    assert gh.pushed == 0 and pub.published == 0


@pytest.mark.adversarial
def test_stale_publication_digest_aborts_safely(ctx, tmp_usf):
    _authorize(ctx)
    gh = FakeGitHub()
    pub = FakePublisher(live_digest="sha256:" + "c" * 64)  # moved under us
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.STALE.value
    assert pub.published == 0  # never force-published on a moved digest
    assert gh.merged == 1  # merge happened; publication correctly aborted


@pytest.mark.adversarial
def test_post_publication_drift_failure_prevents_closure(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher(drift_ok=False))
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.FAILED.value  # drift not reconciled => no closure
    assert rec.authority_digest_after  # publication happened, but closure withheld


@pytest.mark.adversarial
def test_obligation_absence_required_for_closure(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(
        ctx, github=FakeGitHub(), publisher=FakePublisher(obligation_gone=False)
    )
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.FAILED.value  # obligation still present => not closed


@pytest.mark.e2e
def test_coherent_delivery_closes_every_bound_obligation(ctx, tmp_usf):
    _authorize(ctx)
    pub = FakePublisher()
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub)
    rec = coord.deliver(_inp(obligation_ids=["obl-2", "obl-1", "obl-2"]))
    assert rec.state == DeliveryState.COMPLETE.value
    assert rec.obligation_ids == ["obl-1", "obl-2"]
    assert rec.reconciliation["obligations_closed"] == ["obl-1", "obl-2"]


@pytest.mark.adversarial
def test_coherent_delivery_fails_when_any_bound_obligation_remains(ctx, tmp_usf):
    _authorize(ctx)
    pub = FakePublisher()
    pub.obligation_absent = lambda snap, obligation_id: obligation_id != "obl-2"
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub).deliver(
        _inp(obligation_ids=["obl-1", "obl-2"])
    )
    assert rec.state == DeliveryState.FAILED.value
    assert rec.blocked_reason.endswith("obl-2")


@pytest.mark.adversarial
def test_restart_reconciliation_prevents_duplicate_side_effects(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec1 = coord.deliver(_inp())
    assert rec1.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1 and gh.merged == 1 and pub.published == 1
    # Re-running the SAME delivery resumes from persisted COMPLETE state.
    coord2 = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec2 = coord2.deliver(_inp())
    assert rec2.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1 and gh.merged == 1 and pub.published == 1


@pytest.mark.adversarial
def test_uncertain_push_reconciles_exact_remote_head_without_duplicate(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    gh.fail.add("push")
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = coord.deliver(_inp())
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    gh.fail.remove("push")
    # The fake remote reports the reviewed SHA: the lost response is reconciled,
    # so the push is not repeated.
    second = coord.deliver(_inp())
    assert second.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1


@pytest.mark.adversarial
def test_preflight_resume_uses_exact_cas_bound_input(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    gh.fail.add("push")
    first_coordinator = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = first_coordinator.deliver(_inp())
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    assert first.input_ref.startswith("cas:sha256:")
    assert ctx.store.cas_has(first.input_ref)

    gh.fail.remove("push")
    resumed = DeliveryCoordinator(ctx, github=gh, publisher=pub).resume_uncertain()
    assert [record.state for record in resumed] == [DeliveryState.COMPLETE.value]
    assert gh.pushed == 1
    assert pub.published == 1


@pytest.mark.adversarial
def test_crash_after_push_leaves_reconcilable_persisted_intent(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    original_push = gh.push_branch

    def crash_after_push(clone, branch, *, allow_force=False):
        original_push(clone, branch, allow_force=allow_force)
        raise RuntimeError("simulated process loss after remote accepted push")

    gh.push_branch = crash_after_push
    coordinator = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    inp = _inp(set_id="crash-after-push")
    delivery_id = coordinator._delivery_id(inp)
    with pytest.raises(RuntimeError, match="simulated process loss"):
        coordinator.deliver(inp)
    persisted = coordinator.load(delivery_id)
    assert persisted is not None
    assert persisted.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    assert persisted.reconciliation["uncertain_action"] == "push"

    gh.push_branch = original_push
    resumed = DeliveryCoordinator(ctx, github=gh, publisher=pub).resume_uncertain()
    assert [record.state for record in resumed] == [DeliveryState.COMPLETE.value]
    assert gh.pushed == 1


@pytest.mark.adversarial
def test_uncertain_publication_reconciles_live_parity_without_duplicate(ctx, tmp_usf):
    _authorize(ctx)
    gh = FakeGitHub()
    pub = FakePublisher(publish_response_lost=True)
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = coord.deliver(_inp())
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    second = coord.deliver(_inp())
    assert second.state == DeliveryState.COMPLETE.value
    assert pub.published == 1


@pytest.mark.adversarial
def test_committed_gate_repository_and_database_scopes_are_all_required(ctx, tmp_usf):
    gh, pub = FakeGitHub(), FakePublisher()
    ctx.run_authorization = _authz()
    # RunAuthorization alone cannot bypass the committed safety gate.
    rec = DeliveryCoordinator(ctx, github=gh, publisher=pub).deliver(_inp())
    assert rec.state == DeliveryState.BLOCKED.value
    assert "committed safety gate" in rec.blocked_reason

    # A fresh identity under a wrong repository scope is blocked before push.
    _authorize(ctx, repositories=["maldous/other"])
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(
        _inp(set_id="wrong-repository")
    )
    assert "does not cover repository" in rec.blocked_reason

    # Correct repository but wrong database reaches no authority transaction.
    _authorize(ctx, authority_database="OTHER")
    pub = FakePublisher()
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub).deliver(
        _inp(set_id="wrong-database")
    )
    assert "does not cover the live authority database" in rec.blocked_reason
    assert pub.published == 0


@pytest.mark.adversarial
def test_delivery_identity_changes_with_patch_and_assurance_bindings(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    first = coord._delivery_id(_inp())
    assert coord._delivery_id(_inp(diff_text="diff --git a/y b/y\n+2\n")) != first
    assert coord._delivery_id(_inp(validation_receipt_digest="sha256:" + "d" * 64)) != first
    assert coord._delivery_id(_inp(review_receipt_digest="sha256:" + "e" * 64)) != first
    assert coord._delivery_id(_inp(policy_digest="sha256:" + "f" * 64)) != first
    assert coord._delivery_id(_inp(obligation_ids=["obl-1", "obl-2"])) != first


@pytest.mark.adversarial
def test_no_run_authorization_blocks_before_push(ctx, tmp_usf):
    ctx.run_authorization = None  # no operator grant
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.BLOCKED.value
    assert gh.pushed == 0 and gh.merged == 0  # no protected side effect fired


@pytest.mark.adversarial
def test_checked_head_must_equal_reviewed_head(ctx, tmp_usf):
    _authorize(ctx)
    gh = FakeGitHub()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=FakePublisher())
    # After review the PR head changes underneath us.
    orig = gh.commit_with_trailers

    def commit(clone, subject, body, trailers):
        r, sha = orig(clone, subject, body, trailers)
        gh.head = "movedhead999"  # checks/merge will see a different head
        return r, sha

    gh.commit_with_trailers = commit
    rec = coord.deliver(_inp())
    assert rec.state == DeliveryState.BLOCKED.value
    assert gh.merged == 0  # never merged a head that diverged from review
