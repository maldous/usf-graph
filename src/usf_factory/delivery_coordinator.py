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

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json, digest_bytes, short_digest, stable_id
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import DeliveryState, ProtectedAction, RemediationKind, Risk
from .github_delivery import GitHubDelivery
from .models import DeliveryRecord
from .stardog_publication import StardogPublisher
from .validation_evidence import (
    AuthorityEvidenceTransport,
    FactoryValidationReceipt,
    execute_validation_receipt,
    validate_authority_evidence_transport,
)

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
_CONTENT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass
class DeliveryInput:
    """Everything needed to deliver one coherent accepted obligation set."""

    obligation_id: str
    set_id: str
    remediation_kind: RemediationKind
    base_head: str
    expected_pre_publication_digest: str
    obligation_ids: list[str] | None = None
    risk: Risk = Risk.MEDIUM
    # SOURCE_CHANGE: accepted effective diff. VALIDATION_EVIDENCE: an externally
    # produced, digest-verified authority-evidence patch (never a factory receipt).
    diff_text: str = ""
    authority_evidence_verified: bool = False
    validation_passed: bool = False
    review_approved: bool = False
    reviewer_profile_id: str = ""
    authoring_providers: list[str] | None = None
    provider_model_receipts: list[dict[str, Any]] | None = None
    evidence_refs: list[str] | None = None
    validation_receipt_digest: str = ""
    review_receipt_digest: str = ""
    policy_digest: str = ""
    workforce_snapshot_id: str = ""
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
        self.repository_scope = str(getattr(github, "repository_scope", "") or "")

    # ---- persistence ---------------------------------------------------- #

    def _delivery_id(self, inp: DeliveryInput) -> str:
        obligation_ids = sorted(set(inp.obligation_ids or [inp.obligation_id]))
        return stable_id(
            "dlv",
            {
                "obligation_id": inp.obligation_id,
                "obligation_ids": obligation_ids,
                "set_id": inp.set_id,
                "base_head": inp.base_head,
                "expected": inp.expected_pre_publication_digest,
                "remediation_kind": inp.remediation_kind.value,
                "diff_text": inp.diff_text,
                "validation_receipt_digest": inp.validation_receipt_digest,
                "review_receipt_digest": inp.review_receipt_digest,
                "policy_digest": inp.policy_digest,
                "workforce_snapshot_id": inp.workforce_snapshot_id,
                "run_authorization_digest": self._authz_digest(),
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

    @staticmethod
    def _input_payload(inp: DeliveryInput) -> dict[str, Any]:
        return {
            "obligation_id": inp.obligation_id,
            "obligation_ids": sorted(set(inp.obligation_ids or [inp.obligation_id])),
            "set_id": inp.set_id,
            "remediation_kind": inp.remediation_kind.value,
            "base_head": inp.base_head,
            "expected_pre_publication_digest": inp.expected_pre_publication_digest,
            "risk": inp.risk.value,
            "diff_text": inp.diff_text,
            "authority_evidence_verified": inp.authority_evidence_verified,
            "validation_passed": inp.validation_passed,
            "review_approved": inp.review_approved,
            "reviewer_profile_id": inp.reviewer_profile_id,
            "authoring_providers": list(inp.authoring_providers or []),
            "provider_model_receipts": list(inp.provider_model_receipts or []),
            "evidence_refs": list(inp.evidence_refs or []),
            "validation_receipt_digest": inp.validation_receipt_digest,
            "review_receipt_digest": inp.review_receipt_digest,
            "policy_digest": inp.policy_digest,
            "workforce_snapshot_id": inp.workforce_snapshot_id,
            "pr_base_branch": inp.pr_base_branch,
        }

    @staticmethod
    def _input_from_payload(payload: dict[str, Any]) -> DeliveryInput:
        return DeliveryInput(
            obligation_id=str(payload["obligation_id"]),
            obligation_ids=[str(v) for v in payload.get("obligation_ids") or []],
            set_id=str(payload["set_id"]),
            remediation_kind=RemediationKind(str(payload["remediation_kind"])),
            base_head=str(payload["base_head"]),
            expected_pre_publication_digest=str(payload["expected_pre_publication_digest"]),
            risk=Risk(str(payload["risk"])),
            diff_text=str(payload.get("diff_text") or ""),
            authority_evidence_verified=bool(payload.get("authority_evidence_verified")),
            validation_passed=bool(payload.get("validation_passed")),
            review_approved=bool(payload.get("review_approved")),
            reviewer_profile_id=str(payload.get("reviewer_profile_id") or ""),
            authoring_providers=[str(v) for v in payload.get("authoring_providers") or []],
            provider_model_receipts=list(payload.get("provider_model_receipts") or []),
            evidence_refs=[str(v) for v in payload.get("evidence_refs") or []],
            validation_receipt_digest=str(payload.get("validation_receipt_digest") or ""),
            review_receipt_digest=str(payload.get("review_receipt_digest") or ""),
            policy_digest=str(payload.get("policy_digest") or ""),
            workforce_snapshot_id=str(payload.get("workforce_snapshot_id") or ""),
            pr_base_branch=str(payload.get("pr_base_branch") or "main"),
        )

    def _begin_side_effect(self, rec: DeliveryRecord, action: str) -> DeliveryRecord:
        """Persist an uncertain intent before invoking an external side effect."""
        rec.reconciliation = {**rec.reconciliation, "uncertain_action": action}
        rec.state = DeliveryState.UNCERTAIN_SIDE_EFFECT.value
        return self._save(rec, note=f"intent:{action}")

    @staticmethod
    def _clear_side_effect(rec: DeliveryRecord) -> None:
        rec.reconciliation = {
            key: value for key, value in rec.reconciliation.items() if key != "uncertain_action"
        }

    def _hold(self, rec: DeliveryRecord, state: DeliveryState, reason: str) -> DeliveryRecord:
        rec.state = state.value
        rec.blocked_reason = reason
        return self._save(rec, note=reason[:120])

    def _uncertain(self, rec: DeliveryRecord, action: str, reason: str) -> DeliveryRecord:
        rec.reconciliation = {**rec.reconciliation, "uncertain_action": action}
        return self._hold(rec, DeliveryState.UNCERTAIN_SIDE_EFFECT, reason)

    # ---- authorization -------------------------------------------------- #

    def _authz(self) -> Any:
        return self.ctx.run_authorization

    def _authz_digest(self) -> str:
        auth = self._authz()
        return auth.digest() if auth is not None else ""

    def _require(
        self,
        rec: DeliveryRecord,
        action: ProtectedAction,
        risk: Risk,
        *,
        authority_database: str = "",
    ) -> str | None:
        """Return a blocking reason if ``action`` is not authorised for this run, or
        the risk/repository is not covered; None when permitted."""
        auth = self._authz()
        if auth is None:
            return "no RunAuthorization for this run (protected delivery withheld)"
        if not self.ctx.is_gate_enabled(action):
            return f"committed safety gate does not permit {action.value}"
        if not self.ctx.is_action_effective(action):
            return f"RunAuthorization does not permit {action.value} (or it expired)"
        current_authz = self._authz_digest()
        if rec.run_authorization_digest and rec.run_authorization_digest != current_authz:
            return "delivery is bound to a different RunAuthorization"
        if not auth.permits_risk(risk):
            return f"RunAuthorization does not permit risk {risk.value}"
        if action in {ProtectedAction.PUSH_PR, ProtectedAction.MAIN_INTEGRATION} and (
            not self.repository_scope or not auth.covers_repository(self.repository_scope)
        ):
            return (
                f"RunAuthorization does not cover repository {self.repository_scope or '<unknown>'}"
            )
        if action is ProtectedAction.STARDOG_PUBLICATION:
            if not authority_database:
                return "live authority database scope could not be verified"
            if auth.authority_database != authority_database:
                return "RunAuthorization does not cover the live authority database"
        return None

    def _count_states(self, states: set[DeliveryState]) -> int:
        vals = {s.value for s in states}
        authorization_digest = self._authz_digest()
        return sum(
            1
            for _k, row in self.ctx.store.items("delivery_records")
            for st in [row.get("state")]
            if st in vals and row.get("run_authorization_digest") == authorization_digest
        )

    # ---- validation observation + external authority-evidence transport -- #

    def record_validation_receipt(
        self,
        *,
        obligation_id: str,
        subject: str,
        base_head: str,
        authority_digest: str,
        env: dict[str, str] | None = None,
        independent_review: bool = True,
        runner: object | None = None,
    ) -> FactoryValidationReceipt:
        """Execute and persist a factory-local validation observation.

        This method deliberately does not create a DeliveryRecord, Git branch,
        authority patch or publication.  A passing receipt is useful operational
        provenance but cannot satisfy an authority ValidationObligation.
        """
        if self.github is None:
            raise DeliveryError("no GitHub driver wired for evidence generation")
        gen_clone = self.clone_root / f"evidence-{obligation_id.replace(':', '_')}"
        r = self.github.clone_writable(gen_clone, base_head)
        if not r.ok:
            raise DeliveryError(f"evidence clone failed: {r.err[:200]}")
        receipt: FactoryValidationReceipt = execute_validation_receipt(
            self.ctx,
            obligation_id=obligation_id,
            subject=subject,
            clone_path=gen_clone,
            base_head=base_head,
            authority_digest=authority_digest,
            env=env,
            runner=runner,  # type: ignore[arg-type]
        )
        review_ok = False
        if independent_review and receipt.all_passed:
            # A separate clone can corroborate the factory receipt, but still does
            # not admit it into the USF evidence lifecycle.
            rev_clone = self.clone_root / f"evidence-review-{obligation_id.replace(':', '_')}"
            rr = self.github.clone_writable(rev_clone, base_head)
            if rr.ok:
                rreceipt = execute_validation_receipt(
                    self.ctx,
                    obligation_id=obligation_id,
                    subject=subject,
                    clone_path=rev_clone,
                    base_head=base_head,
                    authority_digest=authority_digest,
                    env=env,
                    runner=runner,  # type: ignore[arg-type]
                )
                review_ok = (
                    rreceipt.all_passed and rreceipt.content_dict() == receipt.content_dict()
                )
                receipt.independent_receipt_id = rreceipt.receipt_id
        receipt.independent_revalidation_passed = review_ok
        self.ctx.store.put(
            "factory_validation_receipts",
            receipt.receipt_id,
            receipt.model_dump(mode="json"),
            extra={"obligation_id": obligation_id},
        )
        return receipt

    def deliver_external_authority_evidence(
        self,
        transport: AuthorityEvidenceTransport,
        *,
        artifact_verifier: Callable[[str], bool],
        producer_validation_receipt_ref: str,
        independent_review_receipt_ref: str,
        reviewer_profile_id: str,
        risk: Risk = Risk.LOW,
    ) -> DeliveryRecord:
        """Transport an external authority-evidence candidate through protection.

        The factory validates exact bytes and external artifact availability; it
        does not manufacture admission state.  Canonical graph validation and the
        Stardog transaction remain mandatory later lifecycle stages.
        """
        validate_authority_evidence_transport(transport, artifact_verifier=artifact_verifier)
        try:
            producer_bytes = self.ctx.store.cas_get(producer_validation_receipt_ref)
        except Exception as exc:
            raise ValueError("AUTHORITY_EVIDENCE_VALIDATION_RECEIPT_UNVERIFIED") from exc
        try:
            review_bytes = self.ctx.store.cas_get(independent_review_receipt_ref)
        except Exception as exc:
            raise ValueError("AUTHORITY_EVIDENCE_REVIEW_RECEIPT_UNVERIFIED") from exc
        producer_validation_receipt_digest = digest_bytes(producer_bytes)
        independent_review_receipt_digest = digest_bytes(review_bytes)
        if not _CONTENT_DIGEST.fullmatch(producer_validation_receipt_digest):
            raise ValueError("AUTHORITY_EVIDENCE_VALIDATION_RECEIPT_DIGEST_INVALID")
        if not _CONTENT_DIGEST.fullmatch(independent_review_receipt_digest):
            raise ValueError("AUTHORITY_EVIDENCE_REVIEW_RECEIPT_DIGEST_INVALID")
        if producer_validation_receipt_digest == independent_review_receipt_digest:
            raise ValueError("AUTHORITY_EVIDENCE_REVIEW_NOT_INDEPENDENT")
        return self.deliver(
            DeliveryInput(
                obligation_id=transport.obligation_id,
                set_id=f"authority-evidence-{transport.digest()}",
                remediation_kind=RemediationKind.VALIDATION_EVIDENCE,
                base_head=transport.base_head,
                expected_pre_publication_digest=transport.authority_digest,
                risk=risk,
                diff_text=transport.source_patch,
                authority_evidence_verified=True,
                validation_passed=True,
                review_approved=True,
                reviewer_profile_id=reviewer_profile_id,
                authoring_providers=[transport.producer_id],
                evidence_refs=list(transport.evidence_refs),
                validation_receipt_digest=producer_validation_receipt_digest,
                review_receipt_digest=independent_review_receipt_digest,
            )
        )

    # ---- driver --------------------------------------------------------- #

    def deliver(self, inp: DeliveryInput, *, max_steps: int = 20) -> DeliveryRecord:
        """Run (or resume) the lifecycle to a terminal state. Idempotent: an existing
        record is reconciled and continued from its persisted state."""
        did = self._delivery_id(inp)
        rec = self.load(did)
        if rec is None:
            input_ref = self.ctx.store.cas_put_text(canonical_json(self._input_payload(inp)))
            rec = DeliveryRecord(
                delivery_id=did,
                obligation_id=inp.obligation_id,
                obligation_ids=sorted(set(inp.obligation_ids or [inp.obligation_id])),
                set_id=inp.set_id,
                state=DeliveryState.DISCOVERED.value,
                remediation_kind=inp.remediation_kind.value,
                idempotency_key=did,
                expected_pre_publication_digest=inp.expected_pre_publication_digest,
                repo_base_head=inp.base_head,
                policy_digest=inp.policy_digest,
                run_authorization_digest=self._authz_digest(),
                workforce_snapshot_id=inp.workforce_snapshot_id,
                input_ref=input_ref,
                provider_model_receipts=list(inp.provider_model_receipts or []),
                evidence_refs=list(inp.evidence_refs or []),
                created_at=utc_now_iso(),
            )
            self._save(rec, note="discovered")

        if DeliveryState(rec.state) is DeliveryState.UNCERTAIN_SIDE_EFFECT:
            rec = self._reconcile_uncertain(rec, inp)

        steps = 0
        while DeliveryState(rec.state) in _ACTIVE and steps < max_steps:
            steps += 1
            before = rec.state
            rec = self._advance(rec, inp)
            if rec.state == before:  # no forward progress => stop (blocked/held)
                break
        return rec

    def resume_uncertain(self) -> list[DeliveryRecord]:
        """Reconcile every persisted ambiguous side effect from exact CAS input.

        This is safe to call during preflight.  A missing/corrupt input or changed
        run authorization is held fail-closed instead of reconstructing intent.
        """
        resumed: list[DeliveryRecord] = []
        for row in self.ctx.store.records("delivery_records"):
            if row.get("state") != DeliveryState.UNCERTAIN_SIDE_EFFECT.value:
                continue
            rec = DeliveryRecord.model_validate(row)
            try:
                payload = json.loads(self.ctx.store.cas_get(rec.input_ref))
                inp = self._input_from_payload(payload)
            except Exception as exc:
                resumed.append(
                    self._hold(rec, DeliveryState.BLOCKED, f"delivery input unavailable: {exc}")
                )
                continue
            if rec.run_authorization_digest != self._authz_digest():
                resumed.append(
                    self._hold(
                        rec, DeliveryState.BLOCKED, "RunAuthorization changed during recovery"
                    )
                )
                continue
            rec = self._reconcile_uncertain(rec, inp)
            steps = 0
            while DeliveryState(rec.state) in _ACTIVE and steps < 20:
                steps += 1
                before = rec.state
                rec = self._advance(rec, inp)
                if rec.state == before:
                    break
            resumed.append(rec)
        return resumed

    def _reconcile_uncertain(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        """Resolve an ambiguous external side effect before any retry."""
        action = str(rec.reconciliation.get("uncertain_action") or "")
        clone = self.clone_root / rec.delivery_id
        if action == "push":
            block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
            if block:
                return self._hold(rec, DeliveryState.BLOCKED, block)
            result, remote_sha = self.github.remote_branch_sha(clone, rec.branch)  # type: ignore[union-attr]
            if not result.ok:
                return self._save(rec, note="push reconciliation unavailable")
            if remote_sha == rec.reviewed_head and remote_sha:
                self._clear_side_effect(rec)
                rec.state = DeliveryState.BRANCH_PUSHED.value
                return self._save(rec, note="push reconciled to exact reviewed head")
            if not remote_sha:
                self._clear_side_effect(rec)
                rec.state = DeliveryState.DELIVERY_PREPARED.value
                return self._save(rec, note="push confirmed absent; retry permitted")
            return self._hold(
                rec, DeliveryState.BLOCKED, "remote branch differs from reviewed head"
            )
        if action == "open_pr":
            result, pr = self.github.pr_for_head(clone, rec.branch)  # type: ignore[union-attr]
            if not result.ok:
                return self._save(rec, note="PR reconciliation unavailable")
            if not pr:
                self._clear_side_effect(rec)
                rec.state = DeliveryState.BRANCH_PUSHED.value
                return self._save(rec, note="PR confirmed absent; retry permitted")
            if str(pr.get("headRefOid") or "") != rec.reviewed_head:
                return self._hold(
                    rec, DeliveryState.BLOCKED, "reconciled PR head differs from review"
                )
            number = pr.get("number")
            if not isinstance(number, (int, str)):
                return self._hold(rec, DeliveryState.BLOCKED, "reconciled PR number is absent")
            rec.pr_number = int(number)
            rec.pr_url = str(pr.get("url") or "")
            self._clear_side_effect(rec)
            rec.state = DeliveryState.PR_OPENED.value
            return self._save(rec, note="PR creation reconciled")
        if action == "mark_ready":
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not state:
                return self._save(rec, note="PR readiness reconciliation unavailable")
            if state.get("isDraft") is False:
                rec.reconciliation = {**rec.reconciliation, "pr_ready": True}
            self._clear_side_effect(rec)
            rec.state = DeliveryState.PR_OPENED.value
            return self._save(rec, note="PR readiness reconciled")
        if action == "merge":
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not state:
                return self._save(rec, note="merge reconciliation unavailable")
            if state.get("merged") is True:
                merge = state.get("mergeCommit")
                rec.merge_commit = str(merge.get("oid") or "") if isinstance(merge, dict) else ""
                if not rec.merge_commit:
                    return self._hold(rec, DeliveryState.BLOCKED, "merged PR has no merge commit")
                rec.repo_merge_head = rec.merge_commit
                self._clear_side_effect(rec)
                rec.state = DeliveryState.PR_MERGED.value
                return self._save(rec, note="merge reconciled")
            if str(state.get("state") or "").upper() == "OPEN":
                self._clear_side_effect(rec)
                rec.state = DeliveryState.CI_PASSED.value
                return self._save(rec, note="merge confirmed absent; retry permitted")
            return self._hold(rec, DeliveryState.BLOCKED, "PR closed without a verified merge")
        if action == "publish":
            live, database = self.publisher.read_authority_binding()  # type: ignore[union-attr]
            block = self._require(
                rec,
                ProtectedAction.STARDOG_PUBLICATION,
                inp.risk,
                authority_database=database,
            )
            if block:
                return self._hold(rec, DeliveryState.BLOCKED, block)
            if live == inp.expected_pre_publication_digest:
                self._clear_side_effect(rec)
                rec.state = DeliveryState.AUTHORITY_VALIDATED.value
                return self._save(rec, note="publication confirmed absent; retry permitted")
            drift = self.publisher.drift(self.clone_root / f"{rec.delivery_id}-publish")  # type: ignore[union-attr]
            if drift.ok:
                rec.authority_digest_after = live
                rec.reconciliation = {**rec.reconciliation, "publication_reconciled": drift.data}
                self._clear_side_effect(rec)
                rec.state = DeliveryState.AUTHORITY_PUBLISHED.value
                return self._save(rec, note="publication reconciled by exact source/live parity")
            return self._save(rec, note="publication outcome remains uncertain")
        return self._hold(rec, DeliveryState.BLOCKED, "uncertain side effect has no reconciler")

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
        if (
            inp.remediation_kind is RemediationKind.VALIDATION_EVIDENCE
            and not inp.authority_evidence_verified
        ):
            return self._hold(
                rec,
                DeliveryState.BLOCKED,
                "factory validation receipt is not authority-grade evidence",
            )
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
        # Apply the accepted source diff or an explicitly verified external
        # authority-evidence patch. Factory receipts never reach this branch.
        if inp.diff_text and inp.remediation_kind in {
            RemediationKind.SOURCE_CHANGE,
            RemediationKind.VALIDATION_EVIDENCE,
        }:
            ar = self.github.apply_effective_diff(
                clone, inp.diff_text, patch_path=clone.parent / f"{rec.delivery_id}.patch"
            )
        else:
            return self._hold(rec, DeliveryState.FAILED, "no authorised patch to deliver")
        if not ar.ok:
            return self._hold(rec, DeliveryState.FAILED, f"apply failed: {ar.err[:200]}")
        # Re-derive the diff FROM GIT (authoritative), then branch + commit.
        rec.reconciliation = {
            **rec.reconciliation,
            "rederived_bytes": len(self.github.rederive_diff(clone)),
        }
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
            trailers[f"USF-Model-{i}"] = (
                f"{rcpt.get('provider_id', '?')}/{rcpt.get('actual_model', rcpt.get('model', '?'))}"
            )
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
        self._begin_side_effect(rec, "push")
        pr = self.github.push_branch(clone, rec.branch, allow_force=False)  # type: ignore[union-attr]
        if not pr.ok:
            # Ambiguous push outcome => never blindly retry a merge later.
            return self._uncertain(rec, "push", f"push uncertain: {pr.err[:200]}")
        self._clear_side_effect(rec)
        rec.state = DeliveryState.BRANCH_PUSHED.value
        return self._save(rec, note="branch pushed")

    def _step_open_pr(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        self._begin_side_effect(rec, "open_pr")
        r, number, url = self.github.open_draft_pr(  # type: ignore[union-attr]
            clone,
            base=inp.pr_base_branch,
            head=rec.branch,
            title=f"USF factory: {inp.obligation_id}",
            body=self._pr_body(rec, inp),
        )
        if not r.ok or number is None:
            return self._uncertain(rec, "open_pr", f"open PR uncertain: {r.err[:200]}")
        self._clear_side_effect(rec)
        rec.pr_number = number
        rec.pr_url = url
        rec.state = DeliveryState.PR_OPENED.value
        return self._save(rec, note=f"PR #{number} opened")

    def _step_checks(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        if rec.reconciliation.get("pr_ready") is not True:
            self._begin_side_effect(rec, "mark_ready")
            ready = self.github.mark_ready(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not ready.ok:
                return self._uncertain(
                    rec, "mark_ready", f"mark PR ready uncertain: {ready.err[:200]}"
                )
            self._clear_side_effect(rec)
            rec.reconciliation = {**rec.reconciliation, "pr_ready": True}
            rec.state = DeliveryState.PR_OPENED.value
            self._save(rec, note="PR marked ready")
        r = self.github.wait_for_checks(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if not r.ok:
            return self._hold(
                rec, DeliveryState.FAILED, f"required checks did not pass: {r.err[:200]}"
            )
        checks_result, required_checks = self.github.required_checks(  # type: ignore[union-attr]
            clone,
            rec.pr_number,  # type: ignore[arg-type]
        )
        if not checks_result.ok or not required_checks:
            return self._hold(rec, DeliveryState.BLOCKED, "no verified required CI checks")
        if any(str(check.get("bucket") or "").lower() != "pass" for check in required_checks):
            return self._hold(rec, DeliveryState.FAILED, "a required CI check did not pass")
        checked = self.github.pr_head_sha(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        rec.checked_head = checked
        # The checked head MUST equal the reviewed head (no post-review changes).
        if not checked or not rec.reviewed_head:
            return self._hold(rec, DeliveryState.BLOCKED, "checked or reviewed head is absent")
        if checked != rec.reviewed_head:
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
            return self._hold(
                rec, DeliveryState.BLOCKED, "PR head moved after review; refusing merge"
            )
        if self.publisher is None:
            return self._hold(rec, DeliveryState.BLOCKED, "no Stardog publisher wired")
        # Do not merge a semantic change after its authority premise moved. The
        # binding is checked again after merge and immediately before publication.
        live, authority_database = self.publisher.read_authority_binding()
        publication_block = self._require(
            rec,
            ProtectedAction.STARDOG_PUBLICATION,
            inp.risk,
            authority_database=authority_database,
        )
        if publication_block:
            return self._hold(rec, DeliveryState.BLOCKED, publication_block)
        rec.authority_digest_before = live
        if not inp.expected_pre_publication_digest or live != inp.expected_pre_publication_digest:
            return self._hold(
                rec,
                DeliveryState.STALE,
                "authority digest moved before merge; replan",
            )
        self._begin_side_effect(rec, "merge")
        r, merge_sha = self.github.merge_pr(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if not r.ok:
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if state.get("merged"):
                mc = state.get("mergeCommit")
                merge_sha = str(mc.get("oid") or "") if isinstance(mc, dict) else ""
            else:
                return self._uncertain(rec, "merge", f"merge uncertain: {r.err[:200]}")
        self._clear_side_effect(rec)
        rec.merge_commit = merge_sha
        rec.repo_merge_head = merge_sha
        rec.state = DeliveryState.PR_MERGED.value
        return self._save(rec, note=f"merged {merge_sha[:12]}")

    def _step_validate_authority(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        if self.publisher is None:
            return self._hold(rec, DeliveryState.BLOCKED, "no Stardog publisher wired")
        # Re-read the live digest; it MUST match the expected pre-publication digest.
        live, authority_database = self.publisher.read_authority_binding()
        block = self._require(
            rec,
            ProtectedAction.STARDOG_PUBLICATION,
            inp.risk,
            authority_database=authority_database,
        )
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        rec.authority_digest_before = live
        if not inp.expected_pre_publication_digest or live != inp.expected_pre_publication_digest:
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
            return self._hold(
                rec, DeliveryState.FAILED, f"deterministic tests failed: {tr.detail[:200]}"
            )
        vr = self.publisher.validate_and_rollback(clone, inp.expected_pre_publication_digest)
        if not vr.ok:
            return self._hold(
                rec, DeliveryState.FAILED, f"validate-and-rollback failed: {vr.detail[:200]}"
            )
        rec.reconciliation = {
            **rec.reconciliation,
            "authority_database": authority_database,
            "validate_and_rollback": vr.data,
        }
        rec.state = DeliveryState.AUTHORITY_VALIDATED.value
        return self._save(rec, note="validate-and-rollback ok; contamination 0")

    def _step_publish(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        authority_database = str(rec.reconciliation.get("authority_database") or "")
        block = self._require(
            rec,
            ProtectedAction.STARDOG_PUBLICATION,
            inp.risk,
            authority_database=authority_database,
        )
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
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
            return self._hold(
                rec, DeliveryState.BLOCKED, "max_authority_publications quota reached"
            )
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        # Re-pin immediately before publication; validation may have taken long
        # enough for another coordinator to change authority.
        live, current_database = self.publisher.read_authority_binding()  # type: ignore[union-attr]
        if current_database != authority_database or live != inp.expected_pre_publication_digest:
            return self._hold(
                rec, DeliveryState.STALE, "authority binding changed after validation"
            )
        self._begin_side_effect(rec, "publish")
        pr = self.publisher.publish_committed(  # type: ignore[union-attr]
            clone, inp.expected_pre_publication_digest
        )
        if not pr.ok:
            return self._uncertain(rec, "publish", f"publish uncertain: {pr.detail[:200]}")
        self._clear_side_effect(rec)
        rec.authority_digest_after = str(pr.data.get("postAuthorityDigest") or "")
        validated = rec.reconciliation.get("validate_and_rollback") or {}
        candidate_outcome = validated.get("commitOutcome") if isinstance(validated, dict) else {}
        rec.graphs_published = (
            [str(g) for g in (candidate_outcome.get("candidateGraphs") or [])]
            if isinstance(candidate_outcome, dict)
            else []
        )
        rec.reconciliation = {**rec.reconciliation, "publication": pr.data}
        rec.state = DeliveryState.AUTHORITY_PUBLISHED.value
        return self._save(rec, note=f"published; postDigest={rec.authority_digest_after[:16]}")

    def _step_drift(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        dr = self.publisher.drift(clone)  # type: ignore[union-attr]
        if not dr.ok:
            return self._hold(
                rec, DeliveryState.FAILED, f"source/live drift not reconciled: {dr.detail[:200]}"
            )
        rec.reconciliation = {
            **rec.reconciliation,
            "drift": dr.data,
            "resnapshot_at": utc_now_iso(),
        }
        rec.state = DeliveryState.DRIFT_RECONCILED.value
        return self._save(rec, note="drift reconciled (0 mismatches)")

    def _step_close(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        snap = self.publisher.resnapshot()  # type: ignore[union-attr]
        obligation_ids = sorted(set(inp.obligation_ids or [inp.obligation_id]))
        remaining = [
            obligation_id
            for obligation_id in obligation_ids
            if not self.publisher.obligation_absent(snap, obligation_id)  # type: ignore[union-attr]
        ]
        if remaining:
            return self._hold(
                rec,
                DeliveryState.FAILED,
                "obligation(s) still present after publication: " + ", ".join(remaining),
            )
        rec.reconciliation = {
            **rec.reconciliation,
            "obligation_closed": True,
            "obligations_closed": obligation_ids,
        }
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
