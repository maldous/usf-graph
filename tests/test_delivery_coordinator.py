"""Spec Part B — durable, idempotent delivery coordinator lifecycle.

The GitHub + Stardog boundaries are faked so the REAL coordinator FSM (gating,
idempotent persist-before/after, reconciliation, stale-abort, drift-before-closure)
is exercised end to end without touching a live remote. The same coordinator runs
against real ``git``/``gh``/``npm`` drivers in the live acceptance.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from usf_factory.assurance import persist_assurance_bundle
from usf_factory.canonical import canonical_json, content_digest, digest_bytes, digest_text
from usf_factory.delivery_coordinator import DeliveryCoordinator, DeliveryInput
from usf_factory.enums import DeliveryState, ProtectedAction, RemediationKind, Risk
from usf_factory.github_delivery import CommandResult, GitHubDelivery
from usf_factory.models import ActionableGapIdentity, ValidationReceipt, WaveReview
from usf_factory.run_authorization import RunAuthorization
from usf_factory.stardog_publication import PublishStep

FUTURE = "2999-01-01T00:00:00Z"
EXPECTED_DIGEST = "sha256:" + "a" * 64
AFTER_DIGEST = "sha256:" + "b" * 64


@pytest.mark.e2e
def test_reviewed_commit_bundle_restores_exact_commit_after_workspace_loss(tmp_path, tmp_usf):
    github = GitHubDelivery(origin_url=str(tmp_usf))
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_usf,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    first = tmp_path / "first"
    assert github.clone_writable(first, base).ok
    assert github.create_branch(first, "factory/recovery-fixture").ok
    (first / "GOAL.md").write_text("# GOAL\nrecovered exact bytes\n", encoding="utf-8")
    assert github._git(first, "add", "GOAL.md").ok
    committed, expected = github.commit_with_trailers(first, "fixture", "body", {})
    assert committed.ok and expected
    _bound, _head, expected_tree = github.local_head_and_tree(first)
    bundle_path = tmp_path / "reviewed.bundle"
    exported, payload = github.export_commit_bundle(first, bundle_path)
    assert exported.ok and payload and not bundle_path.exists()
    shutil.rmtree(first)

    restored = tmp_path / "restored"
    assert github.clone_writable(restored, base).ok
    bundle_path.write_bytes(payload)
    assert github.restore_commit_bundle(
        restored,
        bundle_path,
        expected_commit=expected,
        branch="factory/recovery-fixture",
    ).ok
    bound, head, tree = github.local_head_and_tree(restored)
    assert bound.ok and head == expected and tree == expected_tree


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
        max_branch_pushes=10,
        max_pr_creations=10,
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
    exact_merge_supported = True

    def __init__(self):
        self.repository_scope = "maldous/usf-graph"
        self.calls: list[str] = []
        self.pushed = 0
        self.merged = 0
        self.head = "reviewedsha000"
        self.fail: set[str] = set()
        self.pr_exists = False
        self.ready_state = False
        self.remote_merged = False
        self.base_head = "basebranchsha"
        self.merge_tree = "prospectivetree"
        self.prospective_merge = "prospectivemerge"
        self.restored = False
        self.local_head = "basehead000"

    def clone_writable(self, dest, base_head):
        self.calls.append("clone")
        self.local_head = base_head
        return CommandResult("clone" not in self.fail, 0, "", "")

    def apply_effective_diff(self, clone, diff_text, *, patch_path):
        self.calls.append("apply")
        return CommandResult(True, 0, "", "")

    def write_files(self, clone, files):
        self.calls.append("write_files")
        return CommandResult(True, 0, "", "")

    def rederive_diff(self, clone):
        return "diff --git a/x b/x\n+1\n"

    def local_head_and_tree(self, clone):
        head = self.head if self.restored else self.local_head
        return CommandResult(True, 0, "", ""), head, "fixturetree"

    def create_branch(self, clone, branch):
        self.calls.append("branch")
        return CommandResult(True, 0, "", "")

    def commit_with_trailers(self, clone, subject, body, trailers):
        self.calls.append("commit")
        self.trailers = trailers
        return CommandResult(True, 0, self.head, ""), self.head

    def export_commit_bundle(self, clone, bundle_path):
        return CommandResult(True, 0, "", ""), b"fixture-reviewed-commit-bundle"

    def restore_commit_bundle(self, clone, bundle_path, *, expected_commit, branch):
        assert expected_commit == self.head
        self.restored = True
        return CommandResult(True, 0, expected_commit, "")

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
        self.pr_exists = True
        return CommandResult(True, 0, "https://gh/pr/7", ""), 7, "https://gh/pr/7"

    def pr_for_head(self, clone, head):
        return CommandResult(True, 0, "", ""), (
            {
                "number": 7,
                "url": "https://gh/pr/7",
                "headRefOid": self.head,
            }
            if self.pr_exists
            else {}
        )

    def mark_ready(self, clone, pr):
        self.calls.append("ready")
        ok = "ready" not in self.fail
        if ok:
            self.ready_state = True
        return CommandResult(ok, 0, "", "")

    def wait_for_checks(self, clone, pr, *, timeout=900.0):
        self.calls.append("checks")
        return CommandResult("checks" not in self.fail, 0, "", "")

    def required_checks(self, clone, pr):
        self.calls.append("required_checks")
        return CommandResult(True, 0, "", ""), [{"name": "verify", "bucket": "pass"}]

    def pr_head_sha(self, clone, pr):
        return self.head

    def pr_witness(self, clone, pr):
        return CommandResult(True, 0, "", ""), {
            "number": pr,
            "state": "OPEN",
            "isDraft": not self.ready_state,
            "headRefOid": self.head,
            "baseRefOid": self.base_head,
            "prospectiveMergeCommit": self.prospective_merge,
            "prospectiveMergeTree": self.merge_tree,
            "prospectiveBaseParent": self.base_head,
            "prospectiveHeadParent": self.head,
        }

    def merge_pr(self, clone, pr, *, method="squash"):
        self.calls.append("merge")
        self.merged += 1
        ok = "merge" not in self.fail
        if ok:
            self.remote_merged = True
        return CommandResult(ok, 0, "", ""), "mergesha111"

    def pr_state(self, clone, pr):
        return {
            "state": "MERGED" if self.remote_merged else "OPEN",
            "merged": self.remote_merged,
            "isDraft": not self.ready_state,
            "mergeCommit": {"oid": "mergesha111"} if self.remote_merged else None,
            "headRefOid": self.head,
            "baseRefOid": self.base_head,
        }

    def commit_tree(self, clone, commit_sha):
        return CommandResult(True, 0, self.merge_tree, ""), self.merge_tree


class FakePublisher:
    def __init__(
        self,
        *,
        live_digest=EXPECTED_DIGEST,
        drift_ok=True,
        obligation_gone=True,
        publish_response_lost=False,
        candidate_digest=AFTER_DIGEST,
    ):
        self.live_digest = live_digest
        self.drift_ok = drift_ok
        self.obligation_gone = obligation_gone
        self.published = 0
        self.publish_response_lost = publish_response_lost
        self.candidate_digest = candidate_digest

    def publication_containment_ready(self):
        return True

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
                "commitOutcome": {
                    "candidateDigest": self.candidate_digest,
                    "candidateGraphs": ["g1", "g2"],
                },
            },
        )

    def publish_committed(self, clone, expected_authority_digest, expected_candidate_digest):
        assert expected_authority_digest == self.live_digest
        assert expected_candidate_digest == self.candidate_digest
        self.published += 1
        self.live_digest = self.candidate_digest
        if self.publish_response_lost:
            return PublishStep("publish", False, detail="response lost")
        return PublishStep("publish", True, data={"postAuthorityDigest": self.candidate_digest})

    def drift(self, clone):
        return PublishStep("drift", self.drift_ok, data={"mismatches": 0 if self.drift_ok else 3})

    def resnapshot(self):
        return {
            "health": {"database": "USF", "ok": True},
            "work_plan": {
                "schemaVersion": 1,
                "authorityDigest": self.live_digest,
                "gaps": (
                    [] if self.obligation_gone else [{"type": "test-gap", "subject": "obl-1"}]
                ),
                "truncated": False,
            },
        }

    def obligation_absent(self, snap, gap_type, subject):
        import json

        return subject not in json.dumps(snap)


def _inp(ctx, **over):
    diff_text = str(over.pop("diff_text", "diff --git a/x b/x\n+1\n"))
    bind_assurance = bool(over.pop("bind_assurance", True))
    obligation_id = str(over.get("obligation_id", "obl-1"))
    obligation_ids = sorted(set(over.get("obligation_ids") or [obligation_id]))
    raw_gaps = over.get("gap_identities") or [
        ActionableGapIdentity(type="test-gap", subject=oid) for oid in obligation_ids
    ]
    gap_identities = [
        gap if isinstance(gap, ActionableGapIdentity) else ActionableGapIdentity.model_validate(gap)
        for gap in raw_gaps
    ]
    set_id = str(over.get("set_id", "set-1"))
    remediation = over.get("remediation_kind", RemediationKind.SOURCE_CHANGE)
    risk = over.get("risk", Risk.MEDIUM)
    base_head = str(over.get("base_head", "basehead000"))
    authority = str(over.get("expected_pre_publication_digest", EXPECTED_DIGEST))
    patch_ref = ctx.store.cas_put_text(diff_text)
    patch_digest = digest_text(diff_text)
    runner_bindings = {"unit-tests": "fixture-runner-v1"}
    runner_digest = content_digest(runner_bindings)
    toolchain_digest = content_digest({"python": "fixture"})
    validation = ValidationReceipt(
        schema_version=2,
        set_id=set_id,
        gates={"unit-tests": True},
        all_passed=True,
        detail={"unit-tests": "passed"},
        patch_digest=patch_digest,
        patch_ref=patch_ref,
        integration_tree="fixturetree",
        integration_head=base_head,
        repository_base_head=base_head,
        authority_digest=authority,
        required_gate_inventory=["unit-tests"],
        actual_runner_inventory=["unit-tests"],
        runner_bindings=runner_bindings,
        runner_inventory_digest=runner_digest,
        toolchain_bindings={"python": "fixture"},
        toolchain_inventory_digest=toolchain_digest,
    )
    review_context = {"setId": set_id, "effectiveDiff": diff_text}
    review_context_ref = ctx.store.cas_put_text(canonical_json(review_context))
    admission_payload = {"agent_profile_id": "rev-1", "roles": ["reviewer"]}
    admission_ref = ctx.store.cas_put_text(canonical_json(admission_payload))
    review = WaveReview(
        schema_version=2,
        set_id=set_id,
        reviewer_profile_id="rev-1",
        approved=True,
        patch_digest=patch_digest,
        validation_receipt_digest=validation.digest(),
        review_context_digest=content_digest(review_context),
        review_context_ref=review_context_ref,
        reviewer_provider_id="review-provider",
        reviewer_actual_model="review-model",
        reviewer_admission_digest=content_digest(admission_payload),
        reviewer_admission_ref=admission_ref,
        authoring_identities=["author-provider"],
        authoring_providers=["author-provider"],
        independence_determined=True,
    )
    auth_digest = (
        ctx.run_authorization.digest()
        if ctx.run_authorization is not None
        else "sha256:" + "0" * 64
    )
    ctx.store.put(
        "workforce_snapshots",
        "active",
        {
            "_active_id": "workforce-fixture",
            "policy_digest": content_digest({"policy": "fixture"}),
        },
    )
    assurance_ref = assurance_digest = ""
    if bind_assurance:
        assurance_ref, _bundle = persist_assurance_bundle(
            ctx.store,
            set_id=set_id,
            obligation_ids=obligation_ids,
            gap_identities=gap_identities,
            remediation_kind=remediation,
            maximum_risk=risk,
            repository_base_head=base_head,
            expected_authority_digest=authority,
            patch_ref=patch_ref,
            validation=validation,
            review=review,
            policy_digest=content_digest({"policy": "fixture"}),
            workforce_snapshot_id="workforce-fixture",
            run_authorization_digest=auth_digest,
        )
        assurance_digest = assurance_ref.removeprefix("cas:")
    base = dict(
        obligation_id=obligation_id,
        obligation_ids=obligation_ids,
        gap_identities=gap_identities,
        set_id=set_id,
        remediation_kind=remediation,
        base_head=base_head,
        expected_pre_publication_digest=authority,
        risk=risk,
        assurance_bundle_ref=assurance_ref,
        assurance_bundle_digest=assurance_digest,
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
    rec = coord.deliver(_inp(ctx))
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
            ctx,
            remediation_kind=RemediationKind.VALIDATION_EVIDENCE,
            diff_text="diff --git a/x b/x\n+candidate\n",
            bind_assurance=False,
        )
    )
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == "LEGACY_ASSURANCE_UNBOUND"
    assert gh.pushed == 0 and pub.published == 0


@pytest.mark.adversarial
def test_stale_publication_digest_aborts_safely(ctx, tmp_usf):
    _authorize(ctx)
    gh = FakeGitHub()
    pub = FakePublisher(live_digest="sha256:" + "c" * 64)  # moved under us
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(_inp(ctx))
    assert rec.state == DeliveryState.STALE.value
    assert pub.published == 0  # never force-published on a moved digest
    assert gh.merged == 0  # stale authority is detected before main is changed


@pytest.mark.adversarial
def test_post_publication_drift_failure_prevents_closure(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher(drift_ok=False))
    rec = coord.deliver(_inp(ctx))
    assert rec.state == DeliveryState.AUTHORITY_PUBLISHED.value
    assert rec.reconciliation["publication_reconciliation_required"] is True
    assert rec.authority_digest_after  # publication happened, but closure withheld


@pytest.mark.adversarial
def test_obligation_absence_required_for_closure(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(
        ctx, github=FakeGitHub(), publisher=FakePublisher(obligation_gone=False)
    )
    rec = coord.deliver(_inp(ctx))
    assert rec.state == DeliveryState.DRIFT_RECONCILED.value


@pytest.mark.e2e
def test_coherent_delivery_closes_every_bound_obligation(ctx, tmp_usf):
    _authorize(ctx)
    pub = FakePublisher()
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub)
    rec = coord.deliver(_inp(ctx, obligation_ids=["obl-2", "obl-1", "obl-2"]))
    assert rec.state == DeliveryState.COMPLETE.value
    assert rec.obligation_ids == ["obl-1", "obl-2"]
    assert rec.reconciliation["obligations_closed"] == ["obl-1", "obl-2"]


@pytest.mark.adversarial
def test_coherent_delivery_fails_when_any_bound_obligation_remains(ctx, tmp_usf):
    _authorize(ctx)
    pub = FakePublisher()
    pub.obligation_absent = lambda snap, gap_type, subject: subject != "obl-2"
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub).deliver(
        _inp(ctx, obligation_ids=["obl-1", "obl-2"])
    )
    assert rec.state == DeliveryState.DRIFT_RECONCILED.value
    assert rec.blocked_reason.endswith("(test-gap, obl-2)")


@pytest.mark.adversarial
def test_restart_reconciliation_prevents_duplicate_side_effects(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec1 = coord.deliver(_inp(ctx))
    assert rec1.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1 and gh.merged == 1 and pub.published == 1
    # Re-running the SAME delivery resumes from persisted COMPLETE state.
    coord2 = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec2 = coord2.deliver(_inp(ctx))
    assert rec2.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1 and gh.merged == 1 and pub.published == 1


@pytest.mark.adversarial
def test_uncertain_push_reconciles_exact_remote_head_without_duplicate(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    gh.fail.add("push")
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = coord.deliver(_inp(ctx))
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    gh.fail.remove("push")
    # The fake remote reports the reviewed SHA: the lost response is reconciled,
    # so the push is not repeated.
    second = coord.deliver(_inp(ctx))
    assert second.state == DeliveryState.COMPLETE.value
    assert gh.pushed == 1


@pytest.mark.adversarial
def test_preflight_resume_uses_exact_cas_bound_input(ctx, tmp_usf):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    gh.fail.add("push")
    first_coordinator = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = first_coordinator.deliver(_inp(ctx))
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
    inp = _inp(ctx, set_id="crash-after-push")
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
@pytest.mark.parametrize("action", ["open_pr", "mark_ready", "merge"])
def test_crash_after_github_side_effect_reconciles_without_duplicate(ctx, tmp_usf, action):
    _authorize(ctx)
    gh, pub = FakeGitHub(), FakePublisher()
    method_name = {
        "open_pr": "open_draft_pr",
        "mark_ready": "mark_ready",
        "merge": "merge_pr",
    }[action]
    original = getattr(gh, method_name)
    calls = 0

    def crash_after_effect(*args, **kwargs):
        nonlocal calls
        calls += 1
        original(*args, **kwargs)
        raise RuntimeError(f"simulated process loss after {action}")

    setattr(gh, method_name, crash_after_effect)
    coordinator = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    inp = _inp(ctx, set_id=f"crash-after-{action}")
    with pytest.raises(RuntimeError, match=f"after {action}"):
        coordinator.deliver(inp)
    persisted = coordinator.load(coordinator._delivery_id(inp))
    assert persisted is not None
    assert persisted.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    assert persisted.reconciliation["uncertain_action"] == action

    setattr(gh, method_name, original)
    resumed = coordinator.resume_uncertain()
    assert [record.state for record in resumed] == [DeliveryState.COMPLETE.value]
    assert calls == 1


@pytest.mark.adversarial
def test_uncertain_publication_reconciles_live_parity_without_duplicate(ctx, tmp_usf):
    _authorize(ctx)
    gh = FakeGitHub()
    pub = FakePublisher(publish_response_lost=True)
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    first = coord.deliver(_inp(ctx))
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    second = coord.deliver(_inp(ctx))
    assert second.state == DeliveryState.COMPLETE.value
    assert pub.published == 1


@pytest.mark.adversarial
def test_noop_publication_response_loss_remains_uncertain(ctx, tmp_usf):
    _authorize(ctx)
    pub = FakePublisher(
        publish_response_lost=True,
        candidate_digest=EXPECTED_DIGEST,
    )
    coordinator = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub)
    first = coordinator.deliver(_inp(ctx))
    assert first.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    resumed = coordinator.resume_uncertain()[0]
    assert resumed.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    consumption_id = str(resumed.reconciliation["consumption_id"])
    assert ctx.store.get("authorization_consumptions", consumption_id)["status"] == "reserved"
    assert pub.published == 1


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("head", "pre-merge witness changed"),
        ("base", "pre-merge witness changed"),
        ("checks", "pre-merge witness changed"),
    ],
)
def test_premerge_witness_movement_forces_revalidation(ctx, tmp_usf, mutation, expected):
    _authorize(ctx)
    github = FakeGitHub()
    coordinator = DeliveryCoordinator(ctx, github=github, publisher=FakePublisher())
    inp = _inp(ctx, set_id=f"moved-{mutation}")
    checked = coordinator.deliver(inp, max_steps=6)
    assert checked.state == DeliveryState.CI_PASSED.value
    if mutation == "head":
        github.head = "changed-head"
    elif mutation == "base":
        github.base_head = "changed-base"
    else:
        github.required_checks = lambda clone, pr: (
            CommandResult(True, 0, "", ""),
            [{"name": "replacement", "bucket": "pass"}],
        )
    result = coordinator.deliver(inp)
    assert result.state == DeliveryState.BLOCKED.value
    assert expected in result.blocked_reason
    assert github.merged == 0


@pytest.mark.adversarial
def test_unavailable_head_witness_fails_closed_before_merge(ctx, tmp_usf):
    _authorize(ctx)
    github = FakeGitHub()
    github.pr_witness = lambda clone, pr: (CommandResult(False, 1, "", "unavailable"), {})
    result = DeliveryCoordinator(ctx, github=github, publisher=FakePublisher()).deliver(_inp(ctx))
    assert result.state == DeliveryState.BLOCKED.value
    assert result.blocked_reason == "exact PR merge witness unavailable"
    assert github.merged == 0


@pytest.mark.adversarial
def test_production_driver_without_exact_merge_mechanism_stays_blocked(ctx, tmp_usf):
    _authorize(ctx)
    github = FakeGitHub()
    github.exact_merge_supported = False
    result = DeliveryCoordinator(ctx, github=github, publisher=FakePublisher()).deliver(_inp(ctx))
    assert result.state == DeliveryState.BLOCKED.value
    assert result.blocked_reason == "EXACT_GITHUB_MERGE_MECHANISM_UNAVAILABLE"
    assert github.merged == 0


@pytest.mark.adversarial
def test_empty_merge_sha_remains_uncertain(ctx, tmp_usf):
    _authorize(ctx)
    github = FakeGitHub()

    def merge_without_sha(clone, pr, *, method="squash"):
        github.merged += 1
        github.remote_merged = True
        return CommandResult(True, 0, "", ""), ""

    github.merge_pr = merge_without_sha
    result = DeliveryCoordinator(ctx, github=github, publisher=FakePublisher()).deliver(_inp(ctx))
    assert result.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    assert result.reconciliation["uncertain_action"] == "merge"


@pytest.mark.adversarial
def test_merge_response_loss_after_head_change_remains_uncertain(ctx, tmp_usf):
    _authorize(ctx)
    github = FakeGitHub()

    def lost_after_changed_head(clone, pr, *, method="squash"):
        github.merged += 1
        github.remote_merged = True
        github.head = "unreviewed-head"
        return CommandResult(False, 1, "", "response lost"), ""

    github.merge_pr = lost_after_changed_head
    result = DeliveryCoordinator(ctx, github=github, publisher=FakePublisher()).deliver(_inp(ctx))
    assert result.state == DeliveryState.UNCERTAIN_SIDE_EFFECT.value
    assert result.reconciliation["uncertain_action"] == "merge"


@pytest.mark.adversarial
def test_committed_gate_repository_and_database_scopes_are_all_required(ctx, tmp_usf):
    gh, pub = FakeGitHub(), FakePublisher()
    ctx.run_authorization = _authz()
    # RunAuthorization alone cannot bypass the committed safety gate.
    rec = DeliveryCoordinator(ctx, github=gh, publisher=pub).deliver(_inp(ctx))
    assert rec.state == DeliveryState.BLOCKED.value
    assert "committed safety gate" in rec.blocked_reason

    # A fresh identity under a wrong repository scope is blocked before push.
    _authorize(ctx, repositories=["maldous/other"])
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(
        _inp(ctx, set_id="wrong-repository")
    )
    assert "does not cover repository" in rec.blocked_reason

    # Correct repository but wrong database reaches no authority transaction.
    _authorize(ctx, authority_database="OTHER")
    pub = FakePublisher()
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=pub).deliver(
        _inp(ctx, set_id="wrong-database")
    )
    assert "does not cover the live authority database" in rec.blocked_reason
    assert pub.published == 0


@pytest.mark.adversarial
def test_delivery_identity_changes_with_patch_and_assurance_bindings(ctx, tmp_usf):
    _authorize(ctx)
    coord = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    first = coord._delivery_id(_inp(ctx))
    assert coord._delivery_id(_inp(ctx, diff_text="diff --git a/y b/y\n+2\n")) != first
    assert coord._delivery_id(_inp(ctx, set_id="different-assurance")) != first
    assert coord._delivery_id(_inp(ctx, obligation_ids=["obl-1", "obl-2"])) != first


@pytest.mark.adversarial
def test_invented_assurance_digest_is_rejected(ctx, tmp_usf):
    _authorize(ctx)
    inp = _inp(ctx)
    inp.assurance_bundle_digest = "sha256:" + "f" * 64
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(inp)
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == "ASSURANCE_BUNDLE_DIGEST_MISMATCH"


@pytest.mark.adversarial
def test_missing_assurance_receipt_bytes_are_rejected(ctx, tmp_usf):
    _authorize(ctx)
    inp = _inp(ctx)
    bundle = json.loads(ctx.store.cas_get(inp.assurance_bundle_ref))
    bundle["validation_receipt_ref"] = "cas:sha256:" + "d" * 64
    bundle["validation_receipt_digest"] = "sha256:" + "d" * 64
    inp.assurance_bundle_ref = ctx.store.cas_put_text(canonical_json(bundle))
    inp.assurance_bundle_digest = inp.assurance_bundle_ref.removeprefix("cas:")
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(inp)
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == "ASSURANCE_VALIDATION_RECEIPT_UNAVAILABLE"


@pytest.mark.adversarial
def test_modified_assurance_receipt_bytes_are_rejected(ctx, tmp_usf):
    _authorize(ctx)
    inp = _inp(ctx)
    bundle = json.loads(ctx.store.cas_get(inp.assurance_bundle_ref))
    receipt_ref = str(bundle["validation_receipt_ref"])
    hexpart = receipt_ref.split("sha256:", 1)[1]
    receipt_path = ctx.store.cas_dir / hexpart[:2] / hexpart[2:4] / hexpart
    receipt_path.write_bytes(b"modified")
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(inp)
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == "ASSURANCE_VALIDATION_RECEIPT_UNAVAILABLE"


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("base_head", "another-head", "repository_base_head"),
        ("expected_pre_publication_digest", "sha256:" + "e" * 64, "expected_authority_digest"),
        ("obligation_ids", ["another-obligation"], "obligation_ids"),
    ],
)
def test_assurance_from_another_delivery_scope_is_rejected(ctx, tmp_usf, field, value, code):
    _authorize(ctx)
    inp = _inp(ctx)
    setattr(inp, field, value)
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(inp)
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason == f"ASSURANCE_BINDING_MISMATCH:{code}"


@pytest.mark.adversarial
def test_review_cannot_be_reused_for_different_validation_receipt(ctx, tmp_usf):
    _authorize(ctx)
    inp = _inp(ctx)
    bundle = json.loads(ctx.store.cas_get(inp.assurance_bundle_ref))
    review = json.loads(ctx.store.cas_get(bundle["review_receipt_ref"]))
    review["validation_receipt_digest"] = "sha256:" + "9" * 64
    review_ref = ctx.store.cas_put_text(canonical_json(review))
    bundle["review_receipt_ref"] = review_ref
    bundle["review_receipt_digest"] = digest_bytes(ctx.store.cas_get(review_ref))
    inp.assurance_bundle_ref = ctx.store.cas_put_text(canonical_json(bundle))
    inp.assurance_bundle_digest = inp.assurance_bundle_ref.removeprefix("cas:")
    rec = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher()).deliver(inp)
    assert rec.state == DeliveryState.BLOCKED.value
    assert rec.blocked_reason.startswith("ASSURANCE_CROSS_BINDING_MISMATCH")


@pytest.mark.adversarial
def test_no_run_authorization_blocks_before_push(ctx, tmp_usf):
    ctx.run_authorization = None  # no operator grant
    gh, pub = FakeGitHub(), FakePublisher()
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver(_inp(ctx))
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
    rec = coord.deliver(_inp(ctx))
    assert rec.state == DeliveryState.BLOCKED.value
    assert gh.merged == 0  # never merged a head that diverged from review
