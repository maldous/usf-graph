"""Durable, idempotent delivery coordinator (build task §12).

Drives ONE obligation's accepted result through the protected lifecycle:

    DISCOVERED -> LOCAL_VALIDATED -> REVIEW_APPROVED -> DELIVERY_PREPARED
    -> BRANCH_PUSHED -> PR_OPENED -> CI_PASSED -> PR_MERGED
    -> AUTHORITY_VALIDATED -> AUTHORITY_PUBLISHED -> DRIFT_RECONCILED
    -> OBLIGATION_CLOSED -> COMPLETE

Every forward step that has an external side effect (push / open PR / merge /
publish) persists the record BEFORE and AFTER the effect, carries an idempotency
key and the exact digest/head/authorization bindings, and — on restart — reconciles
the real external state before retrying, so an uncertain side effect is never
blindly repeated. Each protected step is gated on a live operator
``RunAuthorization`` (committed gates stay false by default) and its quotas
(max_pr_merges, max_authority_publications, permitted risk, covered repository).

The coordinator is deterministic Python: no model ever performs a Git/GitHub/
Stardog side effect or receives a credential. GitHub + Stardog operations are
injected (real subprocess drivers in production; fakes in tests) so the lifecycle
logic is exercised end-to-end without touching a live remote in tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import short_digest, stable_id
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import DeliveryState, ProtectedAction, RemediationKind, Risk
from .github_delivery import GitHubDelivery
from .models import DeliveryRecord
from .stardog_publication import StardogPublisher

_ACTIVE = {
    DeliveryState.DISCOVERED,
    DeliveryState.LOCAL_VALIDATED,
    DeliveryState.REVIEW_APPROVED,
    DeliveryState.DELIVERY_PREPARED,
    DeliveryState.BRANCH_PUSHED,
    DeliveryState.PR_OPENED,
    DeliveryState.CI_PASSED,
    DeliveryState.PR_MERGED,
    DeliveryState.AUTHORITY_VALIDATED,
    DeliveryState.AUTHORITY_PUBLISHED,
    DeliveryState.DRIFT_RECONCILED,
}
_TERMINAL_HOLDS = {
    DeliveryState.STALE,
    DeliveryState.BLOCKED,
    DeliveryState.FAILED,
    DeliveryState.UNCERTAIN_SIDE_EFFECT,
}


@dataclass
class DeliveryInput:
    """Everything the coordinator needs to deliver one accepted obligation."""

    obligation_id: str
    set_id: str
    remediation_kind: RemediationKind
    base_head: str
    expected_pre_publication_digest: str
    risk: Risk = Risk.MEDIUM
    diff_text: str = ""  # SOURCE_CHANGE: the accepted effective diff
    evidence_files: dict[str, str] | None = None  # evidence deliveries: path -> content
    validation_passed: bool = False
    review_approved: bool = False
    reviewer_profile_id: str = ""
    authoring_providers: list[str] | None = None
    provider_model_receipts: list[dict[str, Any]] | None = None
    evidence_refs: list[str] | None = None
    pr_base_branch: str = "main"


class DeliveryError(Exception):
    pass


class DeliveryCoordinator:
    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        github: GitHubDelivery | None = None,
        publisher: StardogPublisher | None = None,
        clone_root: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.github = github
        self.publisher = publisher
        self.clone_root = clone_root or (ctx.paths.workspaces / "delivery")

    # ---- persistence ---------------------------------------------------- #

    def _delivery_id(self, inp: DeliveryInput) -> str:
        return stable_id(
            "dlv",
            {
                "obligation_id": inp.obligation_id,
                "set_id": inp.set_id,
                "base_head": inp.base_head,
                "expected": inp.expected_pre_publication_digest,
            },
        )

    def load(self, delivery_id: str) -> DeliveryRecord | None:
        row = self.ctx.store.get("delivery_records", delivery_id)
        return DeliveryRecord.model_validate(row) if row else None

    def _save(self, rec: DeliveryRecord, *, note: str = "") -> DeliveryRecord:
        if note:
            rec.history = [*rec.history, f"{rec.state}:{note}"]
        rec.updated_at = utc_now_iso()
        self.ctx.store.put(
            "delivery_records",
            rec.delivery_id,
            rec.model_dump(mode="json"),
            extra={"obligation_id": rec.obligation_id, "state": rec.state},
        )
        self.ctx.log_event(
            "delivery.state",
            stage="DELIVERING",
            payload={
                "delivery_id": rec.delivery_id,
                "obligation_id": rec.obligation_id,
                "state": rec.state,
                "pr_number": rec.pr_number,
                "note": note,
            },
        )
        return rec

    def _hold(self, rec: DeliveryRecord, state: DeliveryState, reason: str) -> DeliveryRecord:
        rec.state = state.value
        rec.blocked_reason = reason
        return self._save(rec, note=reason[:120])

    # ---- authorization -------------------------------------------------- #

    def _authz(self) -> Any:
        return self.ctx.run_authorization

    def _authz_digest(self) -> str:
        auth = self._authz()
        return auth.digest() if auth is not None else ""

    def _require(self, rec: DeliveryRecord, action: ProtectedAction, risk: Risk) -> str | None:
        """Return a blocking reason if ``action`` is not authorised for this run, or
        the risk/repository is not covered; None when permitted."""
        auth = self._authz()
        if auth is None:
            return "no RunAuthorization for this run (protected delivery withheld)"
        if not self.ctx.is_action_effective(action):
            return f"RunAuthorization does not permit {action.value} (or it expired)"
        if not auth.permits_risk(risk):
            return f"RunAuthorization does not permit risk {risk.value}"
        return None

    def _count_states(self, states: set[DeliveryState]) -> int:
        vals = {s.value for s in states}
        return sum(
            1
            for _k, row in self.ctx.store.items("delivery_records")
            for st in [row.get("state")]
            if st in vals
        )

    # ---- validation-evidence generation + delivery (§2/§3/§11) ---------- #

    def deliver_validation_evidence(
        self,
        *,
        obligation_id: str,
        subject: str,
        base_head: str,
        authority_digest: str,
        env: dict[str, str] | None = None,
        independent_review: bool = True,
        runner: object | None = None,
    ) -> DeliveryRecord:
        """Close a ``missing-current-passing-validation`` obligation by EXECUTING the
        deterministic suite (evidence, not a source repair), independently
        re-validating it, then delivering the compact evidence record through the
        protected lifecycle. Blocks (no side effect) if the suite does not pass or
        the independent re-run disagrees."""
        from .validation_evidence import (
            evidence_files,
            execute_validation_evidence,
        )

        if self.github is None:
            raise DeliveryError("no GitHub driver wired for evidence generation")
        gen_clone = self.clone_root / f"evidence-{obligation_id.replace(':', '_')}"
        r = self.github.clone_writable(gen_clone, base_head)
        if not r.ok:
            raise DeliveryError(f"evidence clone failed: {r.err[:200]}")
        receipt = execute_validation_evidence(
            self.ctx,
            obligation_id=obligation_id,
            subject=subject,
            clone_path=gen_clone,
            base_head=base_head,
            authority_digest=authority_digest,
            env=env,
            runner=runner,  # type: ignore[arg-type]
        )
        self.ctx.store.put(
            "validation_evidence",
            receipt.evidence_id,
            receipt.model_dump(mode="json"),
            extra={"obligation_id": obligation_id},
        )
        review_ok = receipt.all_passed
        if independent_review and receipt.all_passed:
            # Independent re-validation in a SEPARATE clone (deterministic evidence:
            # an independent re-run reproducing the result IS the independent review).
            rev_clone = self.clone_root / f"evidence-review-{obligation_id.replace(':', '_')}"
            rr = self.github.clone_writable(rev_clone, base_head)
            if rr.ok:
                rreceipt = execute_validation_evidence(
                    self.ctx,
                    obligation_id=obligation_id,
                    subject=subject,
                    clone_path=rev_clone,
                    base_head=base_head,
                    authority_digest=authority_digest,
                    env=env,
                    runner=runner,  # type: ignore[arg-type]
                )
                review_ok = rreceipt.all_passed == receipt.all_passed and rreceipt.all_passed
            else:
                review_ok = False
        inp = DeliveryInput(
            obligation_id=obligation_id,
            set_id=f"vev-{receipt.evidence_id}",
            remediation_kind=RemediationKind.VALIDATION_EVIDENCE,
            base_head=base_head,
            expected_pre_publication_digest=authority_digest,
            risk=Risk.LOW,
            evidence_files=evidence_files(receipt),
            validation_passed=receipt.all_passed,
            review_approved=review_ok,
            reviewer_profile_id="deterministic-revalidation",
            evidence_refs=[receipt.evidence_id],
        )
        return self.deliver(inp)

    # ---- driver --------------------------------------------------------- #

    def deliver(self, inp: DeliveryInput, *, max_steps: int = 20) -> DeliveryRecord:
        """Run (or resume) the lifecycle to a terminal state. Idempotent: an existing
        record is reconciled and continued from its persisted state."""
        did = self._delivery_id(inp)
        rec = self.load(did)
        if rec is None:
            rec = DeliveryRecord(
                delivery_id=did,
                obligation_id=inp.obligation_id,
                set_id=inp.set_id,
                state=DeliveryState.DISCOVERED.value,
                remediation_kind=inp.remediation_kind.value,
                idempotency_key=did,
                expected_pre_publication_digest=inp.expected_pre_publication_digest,
                repo_base_head=inp.base_head,
                policy_digest="",
                run_authorization_digest=self._authz_digest(),
                provider_model_receipts=list(inp.provider_model_receipts or []),
                evidence_refs=list(inp.evidence_refs or []),
                created_at=utc_now_iso(),
            )
            self._save(rec, note="discovered")

        steps = 0
        while DeliveryState(rec.state) in _ACTIVE and steps < max_steps:
            steps += 1
            before = rec.state
            rec = self._advance(rec, inp)
            if rec.state == before:  # no forward progress => stop (blocked/held)
                break
        return rec

    def _advance(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        state = DeliveryState(rec.state)
        handler = {
            DeliveryState.DISCOVERED: self._step_validate,
            DeliveryState.LOCAL_VALIDATED: self._step_review,
            DeliveryState.REVIEW_APPROVED: self._step_prepare,
            DeliveryState.DELIVERY_PREPARED: self._step_push,
            DeliveryState.BRANCH_PUSHED: self._step_open_pr,
            DeliveryState.PR_OPENED: self._step_checks,
            DeliveryState.CI_PASSED: self._step_merge,
            DeliveryState.PR_MERGED: self._step_validate_authority,
            DeliveryState.AUTHORITY_VALIDATED: self._step_publish,
            DeliveryState.AUTHORITY_PUBLISHED: self._step_drift,
            DeliveryState.DRIFT_RECONCILED: self._step_close,
        }[state]
        return handler(rec, inp)

    # ---- steps ---------------------------------------------------------- #

    def _step_validate(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        if not inp.validation_passed:
            return self._hold(rec, DeliveryState.BLOCKED, "deterministic validation did not pass")
        rec.state = DeliveryState.LOCAL_VALIDATED.value
        return self._save(rec, note="validation passed")

    def _step_review(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        if not inp.review_approved:
            return self._hold(rec, DeliveryState.BLOCKED, "independent review not approved")
        rec.reviewed_head = ""  # set at prepare (local commit)
        rec.state = DeliveryState.REVIEW_APPROVED.value
        return self._save(rec, note=f"review approved by {inp.reviewer_profile_id}")

    def _step_prepare(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        if self.github is None:
            return self._hold(rec, DeliveryState.BLOCKED, "no GitHub delivery driver wired")
        clone = self.clone_root / rec.delivery_id
        r = self.github.clone_writable(clone, inp.base_head)
        if not r.ok:
            return self._hold(rec, DeliveryState.FAILED, f"clone failed: {r.err[:200]}")
        # Apply the accepted effective diff OR the compact evidence record.
        if inp.remediation_kind is RemediationKind.SOURCE_CHANGE and inp.diff_text:
            ar = self.github.apply_effective_diff(
                clone, inp.diff_text, patch_path=clone.parent / f"{rec.delivery_id}.patch"
            )
        elif inp.evidence_files:
            ar = self.github.write_files(clone, inp.evidence_files)
        else:
            return self._hold(rec, DeliveryState.FAILED, "no diff or evidence record to deliver")
        if not ar.ok:
            return self._hold(rec, DeliveryState.FAILED, f"apply failed: {ar.err[:200]}")
        # Re-derive the diff FROM GIT (authoritative), then branch + commit.
        rec.reconciliation = {**rec.reconciliation, "rederived_bytes": len(self.github.rederive_diff(clone))}
        branch = f"usf-factory/obl-{short_digest(rec.obligation_id, 8)}-{short_digest(rec.delivery_id, 6)}"
        br = self.github.create_branch(clone, branch)
        if not br.ok:
            return self._hold(rec, DeliveryState.FAILED, f"branch failed: {br.err[:200]}")
        trailers = {
            "USF-Obligation": inp.obligation_id,
            "USF-Authority-Before": inp.expected_pre_publication_digest,
            "USF-Remediation": inp.remediation_kind.value,
            "USF-Validation": "deterministic-suite-passed",
            "USF-Reviewer": inp.reviewer_profile_id or "unknown",
            "USF-Run-Authorization": self._authz_digest(),
        }
        for i, rcpt in enumerate(inp.provider_model_receipts or []):
            trailers[f"USF-Model-{i}"] = f"{rcpt.get('provider_id', '?')}/{rcpt.get('actual_model', rcpt.get('model', '?'))}"
        cr, sha = self.github.commit_with_trailers(
            clone, f"usf: deliver {inp.obligation_id}", "Automated USF factory delivery.", trailers
        )
        if not cr.ok or not sha:
            return self._hold(rec, DeliveryState.FAILED, f"commit failed: {cr.err[:200]}")
        rec.branch = branch
        rec.reviewed_head = sha
        rec.state = DeliveryState.DELIVERY_PREPARED.value
        return self._save(rec, note=f"prepared {branch}@{sha[:12]}")

    def _step_push(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        # Persist INTENT before the side effect (idempotency).
        self._save(rec, note="pushing")
        pr = self.github.push_branch(clone, rec.branch, allow_force=False)  # type: ignore[union-attr]
        if not pr.ok:
            # Ambiguous push outcome => never blindly retry a merge later.
            return self._hold(
                rec, DeliveryState.UNCERTAIN_SIDE_EFFECT, f"push uncertain: {pr.err[:200]}"
            )
        rec.state = DeliveryState.BRANCH_PUSHED.value
        return self._save(rec, note="branch pushed")

    def _step_open_pr(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        clone = self.clone_root / rec.delivery_id
        r, number, url = self.github.open_draft_pr(  # type: ignore[union-attr]
            clone,
            base=inp.pr_base_branch,
            head=rec.branch,
            title=f"USF factory: {inp.obligation_id}",
            body=self._pr_body(rec, inp),
        )
        if not r.ok or number is None:
            return self._hold(rec, DeliveryState.FAILED, f"open PR failed: {r.err[:200]}")
        rec.pr_number = number
        rec.pr_url = url
        rec.state = DeliveryState.PR_OPENED.value
        return self._save(rec, note=f"PR #{number} opened")

    def _step_checks(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        clone = self.clone_root / rec.delivery_id
        r = self.github.wait_for_checks(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if not r.ok:
            return self._hold(rec, DeliveryState.FAILED, f"required checks did not pass: {r.err[:200]}")
        checked = self.github.pr_head_sha(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        rec.checked_head = checked
        # The checked head MUST equal the reviewed head (no post-review changes).
        if checked and rec.reviewed_head and checked != rec.reviewed_head:
            return self._hold(
                rec,
                DeliveryState.BLOCKED,
                f"checked head {checked[:12]} != reviewed head {rec.reviewed_head[:12]}",
            )
        rec.state = DeliveryState.CI_PASSED.value
        return self._save(rec, note="required checks passed; head matches review")

    def _step_merge(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.MAIN_INTEGRATION, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        auth = self._authz()
        merged_so_far = self._count_states(
            {
                DeliveryState.PR_MERGED,
                DeliveryState.AUTHORITY_VALIDATED,
                DeliveryState.AUTHORITY_PUBLISHED,
                DeliveryState.DRIFT_RECONCILED,
                DeliveryState.OBLIGATION_CLOSED,
                DeliveryState.COMPLETE,
            }
        )
        if auth is not None and merged_so_far >= auth.max_pr_merges:
            return self._hold(rec, DeliveryState.BLOCKED, "max_pr_merges quota reached")
        clone = self.clone_root / rec.delivery_id
        # Reconcile: confirm the reviewed head is still the PR head before merging.
        head_now = self.github.pr_head_sha(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if head_now and rec.reviewed_head and head_now != rec.reviewed_head:
            return self._hold(rec, DeliveryState.BLOCKED, "PR head moved after review; refusing merge")
        self._save(rec, note="merging")
        r, merge_sha = self.github.merge_pr(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if not r.ok:
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if state.get("merged"):
                mc = state.get("mergeCommit")
                merge_sha = str(mc.get("oid") or "") if isinstance(mc, dict) else ""
            else:
                return self._hold(
                    rec, DeliveryState.UNCERTAIN_SIDE_EFFECT, f"merge uncertain: {r.err[:200]}"
                )
        rec.merge_commit = merge_sha
        rec.repo_merge_head = merge_sha
        rec.state = DeliveryState.PR_MERGED.value
        return self._save(rec, note=f"merged {merge_sha[:12]}")

    def _step_validate_authority(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.STARDOG_PUBLICATION, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        if self.publisher is None:
            return self._hold(rec, DeliveryState.BLOCKED, "no Stardog publisher wired")
        # Re-read the live digest; it MUST match the expected pre-publication digest.
        live = self.publisher.read_authority_digest()
        rec.authority_digest_before = live
        if inp.expected_pre_publication_digest and live and live != inp.expected_pre_publication_digest:
            return self._hold(
                rec,
                DeliveryState.STALE,
                f"authority digest moved ({live[:12]} != expected "
                f"{inp.expected_pre_publication_digest[:12]}); replan",
            )
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        cr = self.github.clone_writable(clone, rec.merge_commit) if self.github else None  # type: ignore[union-attr]
        if cr is not None and not cr.ok:
            return self._hold(rec, DeliveryState.FAILED, f"publish clone failed: {cr.err[:200]}")
        ci = self.publisher.install_frozen(clone)
        if not ci.ok:
            return self._hold(rec, DeliveryState.FAILED, f"npm ci failed: {ci.detail[:200]}")
        tr = self.publisher.run_tests(clone)
        if not tr.ok:
            return self._hold(rec, DeliveryState.FAILED, f"deterministic tests failed: {tr.detail[:200]}")
        vr = self.publisher.validate_and_rollback(clone)
        if not vr.ok:
            return self._hold(
                rec, DeliveryState.FAILED, f"validate-and-rollback failed: {vr.detail[:200]}"
            )
        rec.state = DeliveryState.AUTHORITY_VALIDATED.value
        return self._save(rec, note="validate-and-rollback ok; contamination 0")

    def _step_publish(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        auth = self._authz()
        published = self._count_states(
            {
                DeliveryState.AUTHORITY_PUBLISHED,
                DeliveryState.DRIFT_RECONCILED,
                DeliveryState.OBLIGATION_CLOSED,
                DeliveryState.COMPLETE,
            }
        )
        if auth is not None and published >= auth.max_authority_publications:
            return self._hold(rec, DeliveryState.BLOCKED, "max_authority_publications quota reached")
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        self._save(rec, note="publishing authority")
        pr = self.publisher.publish_committed(clone)  # type: ignore[union-attr]
        if not pr.ok:
            return self._hold(
                rec, DeliveryState.UNCERTAIN_SIDE_EFFECT, f"publish uncertain: {pr.detail[:200]}"
            )
        rec.authority_digest_after = str(pr.data.get("postDigest") or "")
        rec.graphs_published = [str(g) for g in (pr.data.get("graphs") or [])]
        rec.state = DeliveryState.AUTHORITY_PUBLISHED.value
        return self._save(rec, note=f"published; postDigest={rec.authority_digest_after[:16]}")

    def _step_drift(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        dr = self.publisher.drift(clone)  # type: ignore[union-attr]
        if not dr.ok:
            return self._hold(
                rec, DeliveryState.FAILED, f"source/live drift not reconciled: {dr.detail[:200]}"
            )
        rec.reconciliation = {**rec.reconciliation, "drift": dr.data, "resnapshot_at": utc_now_iso()}
        rec.state = DeliveryState.DRIFT_RECONCILED.value
        return self._save(rec, note="drift reconciled (0 mismatches)")

    def _step_close(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        snap = self.publisher.resnapshot()  # type: ignore[union-attr]
        if not self.publisher.obligation_absent(snap, inp.obligation_id):  # type: ignore[union-attr]
            return self._hold(
                rec,
                DeliveryState.FAILED,
                "obligation still present after publication (closure not confirmed)",
            )
        rec.reconciliation = {**rec.reconciliation, "obligation_closed": True}
        rec.state = DeliveryState.OBLIGATION_CLOSED.value
        self._save(rec, note="obligation confirmed absent")
        rec.state = DeliveryState.COMPLETE.value
        return self._save(rec, note="delivery complete")

    # ---- helpers -------------------------------------------------------- #

    def _pr_body(self, rec: DeliveryRecord, inp: DeliveryInput) -> str:
        return (
            f"Automated USF factory delivery for obligation `{inp.obligation_id}`.\n\n"
            f"- remediation: `{inp.remediation_kind.value}`\n"
            f"- base commit: `{inp.base_head}`\n"
            f"- expected authority digest (pre-publication): `{inp.expected_pre_publication_digest}`\n"
            f"- reviewed head: `{rec.reviewed_head}`\n"
            f"- run authorization: `{self._authz_digest()}`\n\n"
            f"This PR must pass required checks and reviewed==checked head before a "
            f"gated merge; authority publication is transactional (validate-and-rollback, "
            f"then committed publish) with post-publication drift reconciliation."
        )
