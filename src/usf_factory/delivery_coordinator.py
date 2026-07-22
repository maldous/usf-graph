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
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assurance import VerifiedAssurance, verify_assurance_bundle
from .canonical import canonical_json, require_sha256_digest, short_digest, stable_id
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import DeliveryState, ProtectedAction, RemediationKind, Risk
from .event_store import SideEffectQuotaExceeded
from .github_delivery import GitHubDelivery
from .models import ActionableGapIdentity, AssuranceBundle, DeliveryRecord, RequiredChecksReceipt
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
    DeliveryState.OBLIGATION_CLOSED,
}
_TERMINAL_HOLDS = {
    DeliveryState.STALE,
    DeliveryState.BLOCKED,
    DeliveryState.FAILED,
    DeliveryState.UNCERTAIN_SIDE_EFFECT,
}


@dataclass
class DeliveryInput:
    """Everything needed to deliver one coherent accepted obligation set."""

    obligation_id: str
    set_id: str
    remediation_kind: RemediationKind
    base_head: str
    expected_pre_publication_digest: str
    obligation_ids: list[str] | None = None
    gap_identities: list[ActionableGapIdentity] | None = None
    risk: Risk = Risk.MEDIUM
    # Immutable CAS closure over patch + validation + review.  Caller booleans
    # and caller-supplied receipt digests are intentionally not accepted.
    assurance_bundle_ref: str = ""
    assurance_bundle_digest: str = ""
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
                "gap_identities": [gap.content_dict() for gap in self._gap_identities(inp)],
                "assurance_bundle_ref": inp.assurance_bundle_ref,
                "assurance_bundle_digest": inp.assurance_bundle_digest,
                "run_authorization_digest": self._authz_digest(),
            },
        )

    def load(self, delivery_id: str) -> DeliveryRecord | None:
        row = self.ctx.store.get("delivery_records", delivery_id)
        return DeliveryRecord.model_validate(row) if row else None

    def _save(
        self,
        rec: DeliveryRecord,
        *,
        note: str = "",
        reservation: dict[str, Any] | None = None,
        consume_id: str | None = None,
        release_id: str | None = None,
    ) -> DeliveryRecord:
        previous = self.ctx.store.get("delivery_records", rec.delivery_id)
        from_state = str(previous.get("state") or "") if previous else ""
        if note:
            rec.history = [*rec.history, f"{rec.state}:{note}"]
        rec.updated_at = utc_now_iso()
        revision, transition_ref = self.ctx.store.persist_delivery_transition(
            delivery_id=rec.delivery_id,
            expected_revision=rec.version,
            record_payload=rec.model_dump(mode="json"),
            from_state=from_state,
            to_state=rec.state,
            input_ref=rec.input_ref,
            assurance_bundle_ref=rec.assurance_bundle_ref,
            authorization_digest=rec.run_authorization_digest,
            note_code=note,
            reservation=reservation,
            consume_id=consume_id,
            release_id=release_id,
        )
        rec.version = revision
        rec.transition_ref = transition_ref
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
            "gap_identities": [
                gap.content_dict() for gap in DeliveryCoordinator._gap_identities(inp)
            ],
            "set_id": inp.set_id,
            "remediation_kind": inp.remediation_kind.value,
            "base_head": inp.base_head,
            "expected_pre_publication_digest": inp.expected_pre_publication_digest,
            "risk": inp.risk.value,
            "assurance_bundle_ref": inp.assurance_bundle_ref,
            "assurance_bundle_digest": inp.assurance_bundle_digest,
            "provider_model_receipts": list(inp.provider_model_receipts or []),
            "evidence_refs": list(inp.evidence_refs or []),
            "pr_base_branch": inp.pr_base_branch,
        }

    @staticmethod
    def _input_from_payload(payload: dict[str, Any]) -> DeliveryInput:
        return DeliveryInput(
            obligation_id=str(payload["obligation_id"]),
            obligation_ids=[str(v) for v in payload.get("obligation_ids") or []],
            gap_identities=[
                ActionableGapIdentity.model_validate(v) for v in payload.get("gap_identities") or []
            ],
            set_id=str(payload["set_id"]),
            remediation_kind=RemediationKind(str(payload["remediation_kind"])),
            base_head=str(payload["base_head"]),
            expected_pre_publication_digest=str(payload["expected_pre_publication_digest"]),
            risk=Risk(str(payload["risk"])),
            assurance_bundle_ref=str(payload.get("assurance_bundle_ref") or ""),
            assurance_bundle_digest=str(payload.get("assurance_bundle_digest") or ""),
            provider_model_receipts=list(payload.get("provider_model_receipts") or []),
            evidence_refs=[str(v) for v in payload.get("evidence_refs") or []],
            pr_base_branch=str(payload.get("pr_base_branch") or "main"),
        )

    def _begin_side_effect(
        self,
        rec: DeliveryRecord,
        action: str,
        protected_action: ProtectedAction,
        *,
        quota_name: str = "",
        quota_limit: int | None = None,
    ) -> DeliveryRecord:
        """Persist an uncertain intent before invoking an external side effect."""
        prior_attempts = self.ctx.store.records(
            "authorization_consumptions",
            "delivery_id=? AND effect=?",
            (rec.delivery_id, action),
        )
        attempt = len(prior_attempts) + 1
        consumption_id = stable_id(
            "effect",
            {
                "authorization": rec.run_authorization_digest,
                "delivery": rec.delivery_id,
                "effect": action,
                "attempt": attempt,
            },
        )
        rec.reconciliation = {
            **rec.reconciliation,
            "uncertain_action": action,
            "consumption_id": consumption_id,
        }
        rec.state = DeliveryState.UNCERTAIN_SIDE_EFFECT.value
        try:
            return self._save(
                rec,
                note=f"intent:{action}",
                reservation={
                    "consumption_id": consumption_id,
                    "protected_action": protected_action.value,
                    "effect": action,
                    "attempt": attempt,
                    "quota_name": quota_name,
                    "quota_limit": quota_limit,
                },
            )
        except SideEffectQuotaExceeded as exc:
            rec.reconciliation = {
                key: value
                for key, value in rec.reconciliation.items()
                if key not in {"uncertain_action", "consumption_id"}
            }
            rec.state = DeliveryState.BLOCKED.value
            rec.blocked_reason = str(exc)
            return self._save(rec, note=str(exc))

    @staticmethod
    def _clear_side_effect(rec: DeliveryRecord) -> None:
        rec.reconciliation = {
            key: value
            for key, value in rec.reconciliation.items()
            if key not in {"uncertain_action", "consumption_id"}
        }

    def _complete_side_effect(
        self, rec: DeliveryRecord, state: DeliveryState, note: str
    ) -> DeliveryRecord:
        consumption_id = str(rec.reconciliation.get("consumption_id") or "")
        self._clear_side_effect(rec)
        rec.state = state.value
        return self._save(rec, note=note, consume_id=consumption_id or None)

    def _release_side_effect(
        self, rec: DeliveryRecord, state: DeliveryState, note: str
    ) -> DeliveryRecord:
        """Release quota only after exact reconciliation proves no effect occurred."""
        consumption_id = str(rec.reconciliation.get("consumption_id") or "")
        self._clear_side_effect(rec)
        rec.state = state.value
        return self._save(rec, note=note, release_id=consumption_id or None)

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
        reason = self.ctx.protected_action_reason(
            action,
            risk=risk,
            repository=(
                self.repository_scope
                if action in {ProtectedAction.PUSH_PR, ProtectedAction.MAIN_INTEGRATION}
                else ""
            ),
            authority_database=authority_database,
        )
        if reason:
            return reason
        assert auth is not None
        current_authz = self._authz_digest()
        if rec.run_authorization_digest and rec.run_authorization_digest != current_authz:
            return "delivery is bound to a different RunAuthorization"
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

    def _verified_assurance(self, inp: DeliveryInput) -> VerifiedAssurance:
        if not inp.assurance_bundle_ref or not inp.assurance_bundle_digest:
            raise ValueError("LEGACY_ASSURANCE_UNBOUND")
        verified = verify_assurance_bundle(
            self.ctx.store,
            bundle_ref=inp.assurance_bundle_ref,
            bundle_digest=inp.assurance_bundle_digest,
            set_id=inp.set_id,
            obligation_ids=sorted(set(inp.obligation_ids or [inp.obligation_id])),
            gap_identities=self._gap_identities(inp),
            remediation_kind=inp.remediation_kind,
            maximum_risk=inp.risk,
            repository_base_head=inp.base_head,
            expected_authority_digest=inp.expected_pre_publication_digest,
            run_authorization_digest=self._authz_digest(),
        )
        active = self.ctx.store.get("workforce_snapshots", "active")
        if not active:
            raise ValueError("ASSURANCE_WORKFORCE_SNAPSHOT_UNAVAILABLE")
        if str(active.get("_active_id") or "") != verified.bundle.workforce_snapshot_id:
            raise ValueError("ASSURANCE_WORKFORCE_SNAPSHOT_STALE")
        if str(active.get("policy_digest") or "") != verified.bundle.policy_digest:
            raise ValueError("ASSURANCE_POLICY_DIGEST_STALE")
        return verified

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
        safe_obligation = stable_id("obligation", obligation_id)
        gen_clone = self.clone_root / f"evidence-{safe_obligation}"
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
            rev_clone = self.clone_root / f"evidence-review-{safe_obligation}"
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
        for path in (gen_clone, self.clone_root / f"evidence-review-{safe_obligation}"):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
        return receipt

    def deliver_external_authority_evidence(
        self,
        transport: AuthorityEvidenceTransport,
        *,
        assurance_bundle_ref: str,
        assurance_bundle_digest: str,
    ) -> DeliveryRecord:
        """Transport an external authority-evidence candidate through protection.

        The factory validates exact bytes and external artifact availability; it
        does not manufacture admission state.  Canonical graph validation and the
        Stardog transaction remain mandatory later lifecycle stages.
        """
        validate_authority_evidence_transport(transport, store=self.ctx.store)
        try:
            bundle = AssuranceBundle.model_validate(
                json.loads(self.ctx.store.cas_get(assurance_bundle_ref))
            )
        except Exception as exc:
            raise ValueError("AUTHORITY_EVIDENCE_ASSURANCE_BUNDLE_UNAVAILABLE") from exc
        if bundle.patch_digest != transport.source_patch_digest:
            raise ValueError("AUTHORITY_EVIDENCE_ASSURANCE_PATCH_MISMATCH")
        if bundle.obligation_ids != [transport.obligation_id]:
            raise ValueError("AUTHORITY_EVIDENCE_ASSURANCE_OBLIGATION_MISMATCH")
        return self.deliver(
            DeliveryInput(
                obligation_id=transport.obligation_id,
                obligation_ids=[transport.obligation_id],
                gap_identities=list(bundle.gap_identities),
                set_id=bundle.set_id,
                remediation_kind=RemediationKind.VALIDATION_EVIDENCE,
                base_head=transport.base_head,
                expected_pre_publication_digest=transport.authority_digest,
                risk=bundle.maximum_risk,
                assurance_bundle_ref=assurance_bundle_ref,
                assurance_bundle_digest=assurance_bundle_digest,
                evidence_refs=list(transport.evidence_refs),
            )
        )

    # ---- driver --------------------------------------------------------- #

    def deliver(self, inp: DeliveryInput, *, max_steps: int = 20) -> DeliveryRecord:
        """Run (or resume) the lifecycle to a terminal state. Idempotent: an existing
        record is reconciled and continued from its persisted state."""
        inp.expected_pre_publication_digest = require_sha256_digest(
            inp.expected_pre_publication_digest, "expected pre-publication authority digest"
        )
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
                run_authorization_digest=self._authz_digest(),
                input_ref=input_ref,
                assurance_bundle_ref=inp.assurance_bundle_ref,
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

    def resume_incomplete(self) -> list[DeliveryRecord]:
        """Resume every persisted nonterminal delivery from exact CAS input.

        Legacy active projections without a transition chain block rather than
        receiving fabricated history. Missing workspaces are reconstructed from
        the CAS-bound patch and exact persisted repository inputs before the next
        step. Terminal records are never replayed.
        """
        self.cleanup_terminal_workspaces()
        resumed: list[DeliveryRecord] = []
        for row in sorted(
            self.ctx.store.records("delivery_records"),
            key=lambda item: str(item.get("delivery_id") or ""),
        ):
            state = DeliveryState(str(row.get("state")))
            if state not in _ACTIVE and state is not DeliveryState.UNCERTAIN_SIDE_EFFECT:
                continue
            rec = DeliveryRecord.model_validate(row)
            if rec.version <= 0 or not rec.transition_ref:
                resumed.append(
                    self._hold(rec, DeliveryState.BLOCKED, "LEGACY_DELIVERY_TRANSITION_UNBOUND")
                )
                continue
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
            try:
                self._verified_assurance(inp)
            except ValueError as exc:
                resumed.append(self._hold(rec, DeliveryState.BLOCKED, str(exc)))
                continue
            if state is DeliveryState.UNCERTAIN_SIDE_EFFECT:
                rec = self._reconcile_uncertain(rec, inp)
            elif not self._recover_workspace(rec, inp):
                resumed.append(rec)
                continue
            steps = 0
            while DeliveryState(rec.state) in _ACTIVE and steps < 20:
                steps += 1
                if not self._recover_workspace(rec, inp):
                    break
                before = rec.state
                rec = self._advance(rec, inp)
                if rec.state == before:
                    break
            resumed.append(rec)
        return resumed

    def cleanup_terminal_workspaces(self) -> None:
        """Remove only digest-named factory workspaces for terminal deliveries."""
        terminal = {
            DeliveryState.COMPLETE.value,
            DeliveryState.FAILED.value,
            DeliveryState.BLOCKED.value,
            DeliveryState.STALE.value,
        }
        for row in self.ctx.store.records("delivery_records"):
            delivery_id = str(row.get("delivery_id") or "")
            if row.get("state") not in terminal or not delivery_id.startswith("dlv-"):
                continue
            for suffix in ("", "-publish"):
                path = self.clone_root / f"{delivery_id}{suffix}"
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
            (self.clone_root / f"{delivery_id}.patch").unlink(missing_ok=True)

    def resume_uncertain(self) -> list[DeliveryRecord]:
        """Backward-compatible entry point; all incomplete states are now handled."""

        return self.resume_incomplete()

    def _recover_workspace(self, rec: DeliveryRecord, inp: DeliveryInput) -> bool:
        """Recreate a disposable checkout when the persisted state needs one."""

        state = DeliveryState(rec.state)
        if self.github is None:
            return state in {
                DeliveryState.AUTHORITY_PUBLISHED,
                DeliveryState.DRIFT_RECONCILED,
                DeliveryState.OBLIGATION_CLOSED,
            }
        if state is DeliveryState.DELIVERY_PREPARED:
            clone = self.clone_root / rec.delivery_id
            if clone.is_dir():
                bound, head, tree = self.github.local_head_and_tree(clone)
                if bound.ok and head == rec.reviewed_head and tree == rec.reviewed_tree:
                    return True
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_WORKSPACE_IDENTITY_MISMATCH")
                return False
            bundle_ref = str(rec.reconciliation.get("reviewed_commit_bundle_ref") or "")
            if not bundle_ref.startswith("cas:sha256:"):
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_COMMIT_BUNDLE_UNAVAILABLE")
                return False
            try:
                bundle_bytes = self.ctx.store.cas_get(bundle_ref)
            except Exception:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_COMMIT_BUNDLE_INVALID")
                return False
            result = self.github.clone_writable(clone, inp.base_head)
            if not result.ok:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_CLONE_FAILED")
                return False
            bundle_path = clone.parent / f".recovery-{short_digest(rec.delivery_id, 16)}.bundle"
            restored = None
            try:
                bundle_path.write_bytes(bundle_bytes)
                restored = self.github.restore_commit_bundle(
                    clone,
                    bundle_path,
                    expected_commit=rec.reviewed_head,
                    branch=rec.branch,
                )
            except OSError:
                restored = None
            finally:
                bundle_path.unlink(missing_ok=True)
            if restored is None or not restored.ok:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_COMMIT_IDENTITY_MISMATCH")
                return False
            bound, head, tree = self.github.local_head_and_tree(clone)
            if not bound.ok or head != rec.reviewed_head or tree != rec.reviewed_tree:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_WORKSPACE_IDENTITY_MISMATCH")
                return False
            self._save(rec, note="workspace restored from exact reviewed commit bundle")
            return True
        if state in {
            DeliveryState.BRANCH_PUSHED,
            DeliveryState.PR_OPENED,
            DeliveryState.CI_PASSED,
        }:
            clone = self.clone_root / rec.delivery_id
            if clone.is_dir():
                return True
            result = self.github.clone_writable(clone, rec.reviewed_head)
            if not result.ok:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_REMOTE_CLONE_FAILED")
                return False
        if state in {DeliveryState.AUTHORITY_VALIDATED, DeliveryState.AUTHORITY_PUBLISHED}:
            clone = self.clone_root / f"{rec.delivery_id}-publish"
            if clone.is_dir():
                bound, head, _tree = self.github.local_head_and_tree(clone)
                if bound.ok and head == rec.merge_commit:
                    return True
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_PUBLISH_CLONE_MISMATCH")
                return False
            result = self.github.clone_writable(clone, rec.merge_commit)
            if not result.ok:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_PUBLISH_CLONE_FAILED")
                return False
            if self.publisher is None:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_PUBLISHER_UNAVAILABLE")
                return False
            installed = self.publisher.install_frozen(clone)
            tested = self.publisher.run_tests(clone) if installed.ok else None
            if not installed.ok or tested is None or not tested.ok:
                self._hold(rec, DeliveryState.BLOCKED, "RECOVERY_PUBLISH_CLONE_VALIDATION_FAILED")
                return False
        return True

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
                return self._complete_side_effect(
                    rec, DeliveryState.BRANCH_PUSHED, "push reconciled to exact reviewed head"
                )
            if not remote_sha:
                return self._release_side_effect(
                    rec,
                    DeliveryState.DELIVERY_PREPARED,
                    "push confirmed absent; quota released and retry permitted",
                )
            return self._hold(
                rec, DeliveryState.BLOCKED, "remote branch differs from reviewed head"
            )
        if action == "open_pr":
            result, pr = self.github.pr_for_head(clone, rec.branch)  # type: ignore[union-attr]
            if not result.ok:
                return self._save(rec, note="PR reconciliation unavailable")
            if not pr:
                return self._release_side_effect(
                    rec,
                    DeliveryState.BRANCH_PUSHED,
                    "PR confirmed absent; quota released and retry permitted",
                )
            if str(pr.get("headRefOid") or "") != rec.reviewed_head:
                return self._hold(
                    rec, DeliveryState.BLOCKED, "reconciled PR head differs from review"
                )
            number = pr.get("number")
            if not isinstance(number, (int, str)):
                return self._hold(rec, DeliveryState.BLOCKED, "reconciled PR number is absent")
            rec.pr_number = int(number)
            rec.pr_url = str(pr.get("url") or "")
            return self._complete_side_effect(
                rec, DeliveryState.PR_OPENED, "PR creation reconciled"
            )
        if action == "mark_ready":
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not state:
                return self._save(rec, note="PR readiness reconciliation unavailable")
            if state.get("isDraft") is False:
                rec.reconciliation = {**rec.reconciliation, "pr_ready": True}
                return self._complete_side_effect(
                    rec, DeliveryState.PR_OPENED, "PR readiness reconciled"
                )
            return self._release_side_effect(
                rec,
                DeliveryState.PR_OPENED,
                "PR readiness confirmed absent; quota released and retry permitted",
            )
        if action == "merge":
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not state:
                return self._save(rec, note="merge reconciliation unavailable")
            if state.get("merged") is True:
                if str(state.get("headRefOid") or "") != rec.reviewed_head:
                    return self._hold(
                        rec, DeliveryState.BLOCKED, "merged PR head differs from review"
                    )
                merge = state.get("mergeCommit")
                rec.merge_commit = str(merge.get("oid") or "") if isinstance(merge, dict) else ""
                if not rec.merge_commit:
                    return self._save(rec, note="merged PR has no merge commit; outcome uncertain")
                tree_result, tree = self.github.commit_tree(clone, rec.merge_commit)  # type: ignore[union-attr]
                if not tree_result.ok or tree != rec.tested_merge_tree:
                    return self._save(rec, note="merged commit tree is unavailable or unverified")
                rec.repo_merge_head = rec.merge_commit
                return self._complete_side_effect(rec, DeliveryState.PR_MERGED, "merge reconciled")
            if str(state.get("state") or "").upper() == "OPEN":
                return self._release_side_effect(
                    rec,
                    DeliveryState.CI_PASSED,
                    "merge confirmed absent; quota released and retry permitted",
                )
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
            candidate = str(rec.reconciliation.get("validated_candidate_digest") or "")
            # A response-lost no-op publication cannot be distinguished from
            # the pre-existing live state.  Keep the reservation and outcome
            # uncertain rather than claiming the protected action occurred.
            if candidate == inp.expected_pre_publication_digest:
                return self._save(rec, note="no-op publication outcome remains uncertain")
            if live == candidate and candidate:
                drift = self.publisher.drift(  # type: ignore[union-attr]
                    self.clone_root / f"{rec.delivery_id}-publish"
                )
            else:
                drift = None
            if drift is not None and drift.ok:
                rec.authority_digest_after = live
                rec.reconciliation = {**rec.reconciliation, "publication_reconciled": drift.data}
                return self._complete_side_effect(
                    rec,
                    DeliveryState.AUTHORITY_PUBLISHED,
                    "publication reconciled by exact source/live parity",
                )
            if live == inp.expected_pre_publication_digest and candidate != live:
                return self._release_side_effect(
                    rec,
                    DeliveryState.AUTHORITY_VALIDATED,
                    "publication confirmed absent; quota released and retry permitted",
                )
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
            DeliveryState.OBLIGATION_CLOSED: self._step_complete,
        }[state]
        return handler(rec, inp)

    # ---- steps ---------------------------------------------------------- #

    def _step_validate(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        try:
            assurance = self._verified_assurance(inp)
        except ValueError as exc:
            return self._hold(rec, DeliveryState.BLOCKED, str(exc))
        rec.policy_digest = assurance.bundle.policy_digest
        rec.workforce_snapshot_id = assurance.bundle.workforce_snapshot_id
        rec.state = DeliveryState.LOCAL_VALIDATED.value
        return self._save(rec, note="CAS-bound validation receipt verified")

    def _step_review(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        try:
            assurance = self._verified_assurance(inp)
        except ValueError as exc:
            return self._hold(rec, DeliveryState.BLOCKED, str(exc))
        rec.reviewed_head = ""  # set at prepare (local commit)
        rec.state = DeliveryState.REVIEW_APPROVED.value
        return self._save(
            rec,
            note=f"review receipt verified for {assurance.bundle.reviewer_profile_id}",
        )

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
        try:
            assurance = self._verified_assurance(inp)
        except ValueError as exc:
            return self._hold(rec, DeliveryState.BLOCKED, str(exc))
        # Apply the exact CAS bytes already verified by the assurance bundle.
        if assurance.patch_bytes and inp.remediation_kind in {
            RemediationKind.SOURCE_CHANGE,
            RemediationKind.VALIDATION_EVIDENCE,
        }:
            ar = self.github.apply_effective_diff(
                clone,
                assurance.patch_bytes.decode("utf-8"),
                patch_path=clone.parent / f"{rec.delivery_id}.patch",
            )
        else:
            return self._hold(rec, DeliveryState.FAILED, "no authorised patch to deliver")
        if not ar.ok:
            return self._hold(rec, DeliveryState.FAILED, f"apply failed: {ar.err[:200]}")
        bound = self.github.local_head_and_tree(clone)
        if not bound[0].ok:
            return self._hold(rec, DeliveryState.FAILED, "could not derive staged tree identity")
        _result, integration_head, integration_tree = bound
        if integration_head != assurance.validation.integration_head:
            return self._hold(rec, DeliveryState.BLOCKED, "VALIDATED_INTEGRATION_HEAD_MISMATCH")
        if integration_tree != assurance.validation.integration_tree:
            return self._hold(rec, DeliveryState.BLOCKED, "VALIDATED_INTEGRATION_TREE_MISMATCH")
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
            "USF-Reviewer": assurance.bundle.reviewer_profile_id,
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
        rec.reviewed_tree = integration_tree
        bundle_path = clone.parent / f".recovery-{short_digest(rec.delivery_id, 16)}.bundle"
        bundled, bundle_bytes = self.github.export_commit_bundle(clone, bundle_path)
        if not bundled.ok or not bundle_bytes:
            return self._hold(rec, DeliveryState.FAILED, "RECOVERY_BUNDLE_EXPORT_FAILED")
        rec.reconciliation = {
            **rec.reconciliation,
            "reviewed_commit_bundle_ref": self.ctx.store.cas_put(bundle_bytes),
        }
        rec.state = DeliveryState.DELIVERY_PREPARED.value
        return self._save(rec, note=f"prepared {branch}@{sha[:12]}")

    def _step_push(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        # Persist INTENT before the side effect (idempotency).
        auth = self._authz()
        rec = self._begin_side_effect(
            rec,
            "push",
            ProtectedAction.PUSH_PR,
            quota_name="branch_pushes",
            quota_limit=auth.max_branch_pushes if auth is not None else 0,
        )
        if rec.state == DeliveryState.BLOCKED.value:
            return rec
        pr = self.github.push_branch(clone, rec.branch, allow_force=False)  # type: ignore[union-attr]
        if not pr.ok:
            # Ambiguous push outcome => never blindly retry a merge later.
            return self._uncertain(rec, "push", f"push uncertain: {pr.err[:200]}")
        return self._complete_side_effect(rec, DeliveryState.BRANCH_PUSHED, "branch pushed")

    def _step_open_pr(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        auth = self._authz()
        rec = self._begin_side_effect(
            rec,
            "open_pr",
            ProtectedAction.PUSH_PR,
            quota_name="pr_creations",
            quota_limit=auth.max_pr_creations if auth is not None else 0,
        )
        if rec.state == DeliveryState.BLOCKED.value:
            return rec
        r, number, url = self.github.open_draft_pr(  # type: ignore[union-attr]
            clone,
            base=inp.pr_base_branch,
            head=rec.branch,
            title=f"USF factory: {inp.obligation_id}",
            body=self._pr_body(rec, inp),
        )
        if not r.ok or number is None:
            return self._uncertain(rec, "open_pr", f"open PR uncertain: {r.err[:200]}")
        rec.pr_number = number
        rec.pr_url = url
        return self._complete_side_effect(rec, DeliveryState.PR_OPENED, f"PR #{number} opened")

    def _step_checks(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.PUSH_PR, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        clone = self.clone_root / rec.delivery_id
        if rec.reconciliation.get("pr_ready") is not True:
            rec = self._begin_side_effect(rec, "mark_ready", ProtectedAction.PUSH_PR)
            if rec.state == DeliveryState.BLOCKED.value:
                return rec
            ready = self.github.mark_ready(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if not ready.ok:
                return self._uncertain(
                    rec, "mark_ready", f"mark PR ready uncertain: {ready.err[:200]}"
                )
            rec.reconciliation = {**rec.reconciliation, "pr_ready": True}
            rec = self._complete_side_effect(rec, DeliveryState.PR_OPENED, "PR marked ready")
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
        witness_result, witness = self.github.pr_witness(  # type: ignore[union-attr]
            clone,
            rec.pr_number,  # type: ignore[arg-type]
        )
        if not witness_result.ok or not witness:
            return self._hold(rec, DeliveryState.BLOCKED, "exact PR merge witness unavailable")
        checked = str(witness.get("headRefOid") or "")
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
        checks = sorted(
            (
                {
                    str(k): str(v)
                    for k, v in check.items()
                    if k in {"name", "state", "bucket", "workflow", "link"}
                }
                for check in required_checks
            ),
            key=lambda row: (row.get("workflow", ""), row.get("name", ""), row.get("link", "")),
        )
        try:
            receipt = RequiredChecksReceipt(
                repository=self.repository_scope,
                pr_number=int(rec.pr_number or 0),
                reviewed_head=checked,
                base_head=str(witness.get("baseRefOid") or ""),
                prospective_merge_commit=str(witness.get("prospectiveMergeCommit") or ""),
                prospective_merge_tree=str(witness.get("prospectiveMergeTree") or ""),
                checks=checks,
            )
        except Exception as exc:
            return self._hold(rec, DeliveryState.BLOCKED, f"invalid required-check witness: {exc}")
        rec.required_checks_receipt_ref = self.ctx.store.cas_put_text(
            canonical_json(receipt.content_dict())
        )
        rec.checked_base_head = receipt.base_head
        rec.tested_merge_tree = receipt.prospective_merge_tree
        rec.state = DeliveryState.CI_PASSED.value
        return self._save(rec, note="required checks passed; head matches review")

    def _step_merge(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        block = self._require(rec, ProtectedAction.MAIN_INTEGRATION, inp.risk)
        if block:
            return self._hold(rec, DeliveryState.BLOCKED, block)
        auth = self._authz()
        clone = self.clone_root / rec.delivery_id
        if not bool(getattr(self.github, "exact_merge_supported", False)):
            return self._hold(
                rec, DeliveryState.BLOCKED, "EXACT_GITHUB_MERGE_MECHANISM_UNAVAILABLE"
            )
        try:
            receipt = RequiredChecksReceipt.model_validate_json(
                self.ctx.store.cas_get(rec.required_checks_receipt_ref)
            )
        except Exception:
            return self._hold(rec, DeliveryState.BLOCKED, "required-check receipt unavailable")
        checks_result, checks_now = self.github.required_checks(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        witness_result, witness = self.github.pr_witness(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        current_checks = sorted(
            (
                {
                    str(k): str(v)
                    for k, v in check.items()
                    if k in {"name", "state", "bucket", "workflow", "link"}
                }
                for check in checks_now
            ),
            key=lambda row: (row.get("workflow", ""), row.get("name", ""), row.get("link", "")),
        )
        if not checks_result.ok or not witness_result.ok:
            return self._hold(rec, DeliveryState.BLOCKED, "pre-merge GitHub state unavailable")
        if (
            str(witness.get("headRefOid") or "") != receipt.reviewed_head
            or str(witness.get("baseRefOid") or "") != receipt.base_head
            or str(witness.get("prospectiveMergeTree") or "") != receipt.prospective_merge_tree
            or str(witness.get("prospectiveMergeCommit") or "") != receipt.prospective_merge_commit
            or current_checks != receipt.checks
        ):
            return self._hold(
                rec, DeliveryState.BLOCKED, "pre-merge witness changed; revalidation required"
            )
        if self.publisher is None:
            return self._hold(rec, DeliveryState.BLOCKED, "no Stardog publisher wired")
        if not self.publisher.publication_containment_ready():  # type: ignore[union-attr]
            return self._hold(rec, DeliveryState.BLOCKED, "PUBLICATION_CONTAINMENT_UNAVAILABLE")
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
        rec = self._begin_side_effect(
            rec,
            "merge",
            ProtectedAction.MAIN_INTEGRATION,
            quota_name="pr_merges",
            quota_limit=auth.max_pr_merges if auth is not None else 0,
        )
        if rec.state == DeliveryState.BLOCKED.value:
            return rec
        r, merge_sha = self.github.merge_pr(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        if not r.ok:
            state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
            if state.get("merged"):
                mc = state.get("mergeCommit")
                merge_sha = str(mc.get("oid") or "") if isinstance(mc, dict) else ""
            else:
                return self._uncertain(rec, "merge", f"merge uncertain: {r.err[:200]}")
        if not merge_sha:
            return self._uncertain(rec, "merge", "merge response omitted merge commit SHA")
        merged_state = self.github.pr_state(clone, rec.pr_number)  # type: ignore[union-attr,arg-type]
        tree_result, merged_tree = self.github.commit_tree(clone, merge_sha)  # type: ignore[union-attr]
        if (
            merged_state.get("merged") is not True
            or str(merged_state.get("headRefOid") or "") != rec.reviewed_head
            or not tree_result.ok
            or merged_tree != rec.tested_merge_tree
        ):
            return self._uncertain(rec, "merge", "post-merge head/tree proof unavailable")
        rec.merge_commit = merge_sha
        rec.repo_merge_head = merge_sha
        return self._complete_side_effect(rec, DeliveryState.PR_MERGED, f"merged {merge_sha[:12]}")

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
            "validated_candidate_digest": str(
                (vr.data.get("commitOutcome") or {}).get("candidateDigest") or ""
            ),
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
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        # Re-pin immediately before publication; validation may have taken long
        # enough for another coordinator to change authority.
        live, current_database = self.publisher.read_authority_binding()  # type: ignore[union-attr]
        if current_database != authority_database or live != inp.expected_pre_publication_digest:
            return self._hold(
                rec, DeliveryState.STALE, "authority binding changed after validation"
            )
        rec = self._begin_side_effect(
            rec,
            "publish",
            ProtectedAction.STARDOG_PUBLICATION,
            quota_name="authority_publications",
            quota_limit=auth.max_authority_publications if auth is not None else 0,
        )
        if rec.state == DeliveryState.BLOCKED.value:
            return rec
        pr = self.publisher.publish_committed(  # type: ignore[union-attr]
            clone,
            inp.expected_pre_publication_digest,
            str(rec.reconciliation.get("validated_candidate_digest") or ""),
        )
        if not pr.ok:
            return self._uncertain(rec, "publish", f"publish uncertain: {pr.detail[:200]}")
        rec.authority_digest_after = str(pr.data.get("postAuthorityDigest") or "")
        validated = rec.reconciliation.get("validate_and_rollback") or {}
        candidate_outcome = validated.get("commitOutcome") if isinstance(validated, dict) else {}
        rec.graphs_published = (
            [str(g) for g in (candidate_outcome.get("candidateGraphs") or [])]
            if isinstance(candidate_outcome, dict)
            else []
        )
        rec.reconciliation = {**rec.reconciliation, "publication": pr.data}
        rec = self._complete_side_effect(
            rec,
            DeliveryState.AUTHORITY_PUBLISHED,
            f"published; postDigest={rec.authority_digest_after[:16]}",
        )
        live_after, database_after = self.publisher.read_authority_binding()  # type: ignore[union-attr]
        if database_after != authority_database or live_after != rec.authority_digest_after:
            rec.blocked_reason = "published authority binding requires reconciliation"
            rec.reconciliation = {
                **rec.reconciliation,
                "publication_reconciliation_required": True,
                "observed_database_after": database_after,
                "observed_digest_after": live_after,
            }
            return self._save(rec, note="PUBLICATION_RECONCILIATION_REQUIRED")
        return rec

    def _step_drift(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        clone = self.clone_root / f"{rec.delivery_id}-publish"
        dr = self.publisher.drift(clone)  # type: ignore[union-attr]
        if not dr.ok:
            rec.blocked_reason = f"source/live drift not reconciled: {dr.detail[:200]}"
            rec.reconciliation = {
                **rec.reconciliation,
                "publication_reconciliation_required": True,
            }
            # Publication is known to have occurred. Preserve that recoverable
            # state and retry reconciliation on a later authorized cycle.
            return self._save(rec, note="PUBLICATION_RECONCILIATION_REQUIRED")
        live_after, database_after = self.publisher.read_authority_binding()  # type: ignore[union-attr]
        if live_after != rec.authority_digest_after or database_after != str(
            rec.reconciliation.get("authority_database") or ""
        ):
            rec.blocked_reason = "authority binding moved during drift reconciliation"
            rec.reconciliation = {
                **rec.reconciliation,
                "publication_reconciliation_required": True,
                "observed_database_after_drift": database_after,
                "observed_digest_after_drift": live_after,
            }
            return self._save(rec, note="PUBLICATION_RECONCILIATION_REQUIRED")
        rec.reconciliation = {
            **rec.reconciliation,
            "drift": dr.data,
            "resnapshot_at": utc_now_iso(),
        }
        rec.state = DeliveryState.DRIFT_RECONCILED.value
        return self._save(rec, note="drift reconciled (0 mismatches)")

    def _step_close(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        snap = self.publisher.resnapshot()  # type: ignore[union-attr]
        work_plan = snap.get("work_plan") if isinstance(snap, dict) else None
        health = snap.get("health") if isinstance(snap, dict) else None
        if (
            not isinstance(work_plan, dict)
            or work_plan.get("authorityDigest") != rec.authority_digest_after
            or not isinstance(health, dict)
            or str(health.get("database") or "")
            != str(rec.reconciliation.get("authority_database") or "")
        ):
            rec.blocked_reason = "POST_PUBLICATION_WORK_PLAN_BINDING_MISMATCH"
            return self._save(rec, note=rec.blocked_reason)
        gap_identities = self._gap_identities(inp)
        remaining = [
            gap
            for gap in gap_identities
            if not self.publisher.obligation_absent(snap, gap.type, gap.subject)  # type: ignore[union-attr]
        ]
        if remaining:
            rec.blocked_reason = "gap(s) still actionable after publication: " + ", ".join(
                f"({gap.type}, {gap.subject})" for gap in remaining
            )
            return self._save(rec, note="POST_PUBLICATION_CLOSURE_PENDING")
        rec.reconciliation = {
            **rec.reconciliation,
            "obligation_closed": True,
            "obligations_closed": sorted({gap.subject for gap in gap_identities}),
            "gaps_closed": [gap.content_dict() for gap in gap_identities],
        }
        rec.state = DeliveryState.OBLIGATION_CLOSED.value
        return self._save(rec, note="obligation confirmed absent")

    def _step_complete(self, rec: DeliveryRecord, inp: DeliveryInput) -> DeliveryRecord:
        if rec.reconciliation.get("obligation_closed") is not True:
            return self._hold(
                rec, DeliveryState.BLOCKED, "OBLIGATION_CLOSED_STATE_WITHOUT_CLOSURE_PROOF"
            )
        rec.state = DeliveryState.COMPLETE.value
        saved = self._save(rec, note="delivery complete")
        self.cleanup_terminal_workspaces()
        return saved

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

    @staticmethod
    def _gap_identities(inp: DeliveryInput) -> list[ActionableGapIdentity]:
        values = inp.gap_identities or []
        unique = {(gap.type, gap.subject): gap for gap in values}
        return [unique[key] for key in sorted(unique)]
