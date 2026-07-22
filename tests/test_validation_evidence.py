"""Factory receipts and external authority-evidence transport boundaries."""

from __future__ import annotations

import pytest

from test_delivery_coordinator import FakeGitHub, FakePublisher, _authorize
from usf_factory.canonical import digest_bytes, digest_text
from usf_factory.delivery_coordinator import DeliveryCoordinator
from usf_factory.enums import DeliveryState
from usf_factory.github_delivery import CommandResult
from usf_factory.validation_evidence import (
    AuthorityEvidenceTransport,
    compact_receipt_rdf,
    execute_validation_receipt,
)

SUBJECT = "urn:usf:validationobligation:repositoryexternalartefactmaterialisation"
AUTHORITY_DIGEST = "sha256:" + "a" * 64
ARTIFACT_DIGEST = "sha256:" + "b" * 64
BASE_HEAD = "c" * 40
EVIDENCE_REF = "urn:usf:evidenceresult:external-materialisation-validation"
PRODUCER = "urn:usf:validator:external-materialisation-validator"
VALIDATION_RECEIPT_BYTES = b"producer validation receipt\n"
REVIEW_RECEIPT_BYTES = b"independent review receipt\n"
VALIDATION_RECEIPT_DIGEST = digest_bytes(VALIDATION_RECEIPT_BYTES)
REVIEW_RECEIPT_DIGEST = digest_bytes(REVIEW_RECEIPT_BYTES)


def _receipt_refs(ctx):
    return ctx.store.cas_put(VALIDATION_RECEIPT_BYTES), ctx.store.cas_put(REVIEW_RECEIPT_BYTES)


class FakeRunner:
    def __init__(self, *, install_ok=True, test_ok=True, out="42 passing\n0 failing\n"):
        self.install_ok = install_ok
        self.test_ok = test_ok
        self.out = out
        self.calls: list[list[str]] = []

    def run(self, args, *, cwd=None, env=None, timeout=600.0):
        self.calls.append(list(args))
        if args[:2] == ["npm", "ci"]:
            return CommandResult(self.install_ok, 0 if self.install_ok else 1, "", "")
        return CommandResult(self.test_ok, 0 if self.test_ok else 1, self.out, "")


def _authority_patch(*, include_factory_receipt: bool = False) -> str:
    factory_line = (
        "+<urn:factory:receipt> a <urn:usf-factory:ontology:ValidationExecutionReceipt> .\n"
        if include_factory_receipt
        else ""
    )
    return (
        "diff --git a/semantic-model/assurance/evidence.trig "
        "b/semantic-model/assurance/evidence.trig\n"
        "--- a/semantic-model/assurance/evidence.trig\n"
        "+++ b/semantic-model/assurance/evidence.trig\n"
        "@@ -1,0 +1,8 @@\n"
        f'+<{SUBJECT}> <urn:usf:ontology:canonicalName> "materialisation" .\n'
        f"+<urn:execution:x> a <urn:usf:ontology:ValidationExecution> ; "
        f"<urn:usf:ontology:executesValidation> <{SUBJECT}> ; "
        f"<urn:usf:ontology:producesValidationResult> <urn:result:x> ; "
        f"<urn:usf:ontology:evaluatedByValidator> <{PRODUCER}> ; "
        f'<urn:usf:ontology:authorityDigest> "{AUTHORITY_DIGEST}" ; '
        f'<urn:usf:ontology:implementationCommit> "{BASE_HEAD}" .\n'
        "+<urn:result:x> a <urn:usf:ontology:ValidationResult> ; "
        f"<urn:usf:ontology:entersEvidenceLifecycleAs> <{EVIDENCE_REF}> .\n"
        f"+<{EVIDENCE_REF}> a <urn:usf:ontology:ValidationEvidence> ; "
        f"<urn:usf:ontology:applicableToObligation> <{SUBJECT}> ; "
        f'<urn:usf:ontology:contentDigest> "{ARTIFACT_DIGEST}" .\n' + factory_line
    )


def _transport(
    *, patch: str | None = None, digest: str | None = None
) -> AuthorityEvidenceTransport:
    body = patch if patch is not None else _authority_patch()
    return AuthorityEvidenceTransport(
        obligation_id=SUBJECT,
        base_head=BASE_HEAD,
        authority_digest=AUTHORITY_DIGEST,
        producer_id=PRODUCER,
        source_patch=body,
        source_patch_digest=digest or digest_text(body),
        artifact_digests=[ARTIFACT_DIGEST],
        evidence_refs=[EVIDENCE_REF],
    )


@pytest.mark.unit
def test_execute_validation_receipt_pass(ctx, tmp_usf):
    receipt = execute_validation_receipt(
        ctx,
        obligation_id=SUBJECT,
        subject=SUBJECT,
        clone_path=tmp_usf,
        base_head="base000",
        authority_digest=AUTHORITY_DIGEST,
        runner=FakeRunner(),
    )
    assert receipt.all_passed is True
    assert receipt.checks == {"install": True, "deterministic-suite": True}
    assert receipt.passing_count == 42 and receipt.failing_count == 0
    assert receipt.receipt_id.startswith("fvr-")


@pytest.mark.adversarial
def test_execute_validation_receipt_install_failure_fails_closed(ctx, tmp_usf):
    receipt = execute_validation_receipt(
        ctx,
        obligation_id=SUBJECT,
        subject=SUBJECT,
        clone_path=tmp_usf,
        base_head="base000",
        authority_digest=AUTHORITY_DIGEST,
        runner=FakeRunner(install_ok=False),
    )
    assert receipt.all_passed is False
    assert receipt.checks["deterministic-suite"] is False


@pytest.mark.unit
def test_compact_receipt_rdf_is_deterministic_and_not_authority_evidence(ctx, tmp_usf):
    receipt = execute_validation_receipt(
        ctx,
        obligation_id=SUBJECT,
        subject=SUBJECT,
        clone_path=tmp_usf,
        base_head="base000",
        authority_digest=AUTHORITY_DIGEST,
        runner=FakeRunner(),
    )
    first = compact_receipt_rdf(receipt)
    second = compact_receipt_rdf(receipt)
    assert first == second
    assert "factory:ValidationExecutionReceipt" in first
    assert "urn:usf:ontology:ValidationEvidence" not in first
    assert "ev:ValidationEvidence" not in first


@pytest.mark.e2e
def test_record_validation_receipt_has_no_delivery_or_publication(ctx, tmp_usf):
    _authorize(ctx)
    github, publisher = FakeGitHub(), FakePublisher(live_digest=AUTHORITY_DIGEST)
    coordinator = DeliveryCoordinator(ctx, github=github, publisher=publisher)
    receipt = coordinator.record_validation_receipt(
        obligation_id=SUBJECT,
        subject=SUBJECT,
        base_head="base000",
        authority_digest=AUTHORITY_DIGEST,
        runner=FakeRunner(),
    )
    assert receipt.all_passed is True
    assert receipt.independent_revalidation_passed is True
    assert github.pushed == 0 and github.merged == 0 and publisher.published == 0
    rows = list(ctx.store.items("factory_validation_receipts"))
    assert rows and rows[0][1]["obligation_id"] == SUBJECT


@pytest.mark.e2e
def test_verified_external_authority_evidence_uses_protected_patch_lifecycle(ctx, tmp_usf):
    _authorize(ctx)
    github, publisher = FakeGitHub(), FakePublisher(live_digest=AUTHORITY_DIGEST)
    coordinator = DeliveryCoordinator(ctx, github=github, publisher=publisher)
    producer_ref, review_ref = _receipt_refs(ctx)
    record = coordinator.deliver_external_authority_evidence(
        _transport(),
        artifact_verifier=lambda item: item == ARTIFACT_DIGEST,
        producer_validation_receipt_ref=producer_ref,
        independent_review_receipt_ref=review_ref,
        reviewer_profile_id="independent-authority-evidence-reviewer",
    )
    assert record.state == DeliveryState.COMPLETE.value
    assert record.remediation_kind == "VALIDATION_EVIDENCE"
    assert "apply" in github.calls and "write_files" not in github.calls


@pytest.mark.adversarial
def test_external_authority_evidence_rejects_altered_patch(ctx, tmp_usf):
    coordinator = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    producer_ref, review_ref = _receipt_refs(ctx)
    with pytest.raises(ValueError, match="AUTHORITY_EVIDENCE_PATCH_DIGEST_MISMATCH"):
        coordinator.deliver_external_authority_evidence(
            _transport(digest="sha256:" + "c" * 64),
            artifact_verifier=lambda _item: True,
            producer_validation_receipt_ref=producer_ref,
            independent_review_receipt_ref=review_ref,
            reviewer_profile_id="reviewer",
        )


@pytest.mark.adversarial
def test_external_authority_evidence_rejects_unverified_artifact(ctx, tmp_usf):
    coordinator = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    producer_ref, review_ref = _receipt_refs(ctx)
    with pytest.raises(ValueError, match="AUTHORITY_EVIDENCE_ARTIFACT_UNVERIFIED"):
        coordinator.deliver_external_authority_evidence(
            _transport(),
            artifact_verifier=lambda _item: False,
            producer_validation_receipt_ref=producer_ref,
            independent_review_receipt_ref=review_ref,
            reviewer_profile_id="reviewer",
        )


@pytest.mark.adversarial
def test_external_authority_evidence_requires_verifiable_receipt_bytes(ctx, tmp_usf):
    coordinator = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    _producer_ref, review_ref = _receipt_refs(ctx)
    with pytest.raises(ValueError, match="AUTHORITY_EVIDENCE_VALIDATION_RECEIPT_UNVERIFIED"):
        coordinator.deliver_external_authority_evidence(
            _transport(),
            artifact_verifier=lambda _item: True,
            producer_validation_receipt_ref="cas:sha256:" + "d" * 64,
            independent_review_receipt_ref=review_ref,
            reviewer_profile_id="reviewer",
        )


@pytest.mark.adversarial
def test_factory_receipt_cannot_enter_authority_evidence_transport(ctx, tmp_usf):
    patch = _authority_patch(include_factory_receipt=True)
    coordinator = DeliveryCoordinator(ctx, github=FakeGitHub(), publisher=FakePublisher())
    producer_ref, review_ref = _receipt_refs(ctx)
    with pytest.raises(ValueError, match="FACTORY_RECEIPT_IS_NOT_AUTHORITY_EVIDENCE"):
        coordinator.deliver_external_authority_evidence(
            _transport(patch=patch),
            artifact_verifier=lambda _item: True,
            producer_validation_receipt_ref=producer_ref,
            independent_review_receipt_ref=review_ref,
            reviewer_profile_id="reviewer",
        )
