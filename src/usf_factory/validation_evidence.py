"""Factory validation receipts and authority-evidence transport validation.

The factory may execute the deterministic ``usf-graph`` suite and record what it
observed.  That record is a factory-internal execution receipt: it is not
``usf:ValidationEvidence``, is not admitted evidence, and cannot close a live
authority obligation.

Genuine authority evidence is produced outside this module and may enter the
protected delivery lifecycle only through :class:`AuthorityEvidenceTransport`.
The transport binds the exact source patch and external artifact digests; the
canonical graph compiler, SHACL, publication transaction and post-publication
reconciliation remain the authority-grade admission boundary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import Field

from .canonical import digest_bytes, digest_text, stable_id
from .clock import utc_now_iso
from .context import RuntimeContext
from .github_delivery import (
    CommandResult,
    CommandRunner,
    SubprocessRunner,
    restricted_subprocess_environment,
)
from .models import FactoryModel

# The canonical deterministic suite entry point in usf-graph (package.json).
_SUITE_INSTALL = ("npm", "ci")
_SUITE_TEST = ("npm", "test")
# Extract a "N passing" / "N failing" tally from common test-runner output.
_PASS_RE = re.compile(r"(\d+)\s+pass", re.I)
_FAIL_RE = re.compile(r"(\d+)\s+fail", re.I)


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class FactoryValidationReceipt(FactoryModel):
    """Content-addressed observation of a factory-run deterministic validation.

    The name is intentionally explicit: this receipt is operational provenance,
    not authority-grade evidence and not an evidence-admission decision.
    """

    obligation_id: str
    subject: str = ""
    base_head: str
    authority_digest: str = ""
    checks: dict[str, bool] = Field(default_factory=dict)
    all_passed: bool = False
    passing_count: int = 0
    failing_count: int = 0
    detail: dict[str, str] = Field(default_factory=dict)
    independent_revalidation_passed: bool = False
    independent_receipt_id: str = ""
    produced_at: str = ""

    _volatile_fields = frozenset({"produced_at"})

    @property
    def receipt_id(self) -> str:
        return stable_id("fvr", self.content_dict())


class AuthorityEvidenceArtifact(FactoryModel):
    """Immutable artifact bytes fetched from the factory CAS."""

    locator: str
    artifact_digest: str
    byte_size: int = Field(ge=0)


class AuthorityEvidenceAttestation(FactoryModel):
    """Producer or independent-review statement over exact artifact bytes."""

    schema_version: int = 1
    role: str
    identity: str
    provider_id: str
    obligation_id: str
    base_head: str
    authority_digest: str
    source_patch_digest: str
    artifact_digests: list[str]
    accepted: bool


class AuthorityEvidenceTransport(FactoryModel):
    """Exact externally produced authority-evidence candidate for transport.

    The source patch is carried as bytes-in-text and must reference immutable
    artifacts. Validation here proves transport integrity only; semantic
    admission still occurs through the canonical ``usf-graph`` transaction.
    """

    obligation_id: str
    base_head: str
    authority_digest: str
    producer_id: str
    producer_provider_id: str
    reviewer_id: str
    reviewer_provider_id: str
    source_patch: str
    source_patch_digest: str
    artifacts: list[AuthorityEvidenceArtifact] = Field(default_factory=list)
    producer_attestation_ref: str
    reviewer_attestation_ref: str
    evidence_refs: list[str] = Field(default_factory=list)


def validate_authority_evidence_transport(
    transport: AuthorityEvidenceTransport,
    *,
    store: object,
) -> None:
    """Fail closed unless the exact external evidence candidate is transportable."""

    if not transport.obligation_id.startswith("urn:"):
        raise ValueError("AUTHORITY_EVIDENCE_OBLIGATION_INVALID")
    if not _GIT_SHA.fullmatch(transport.base_head) or not transport.producer_id.startswith("urn:"):
        raise ValueError("AUTHORITY_EVIDENCE_PROVENANCE_MISSING")
    if not transport.reviewer_id.startswith("urn:"):
        raise ValueError("AUTHORITY_EVIDENCE_REVIEW_PROVENANCE_MISSING")
    if (
        transport.producer_id == transport.reviewer_id
        or transport.producer_provider_id == transport.reviewer_provider_id
    ):
        raise ValueError("AUTHORITY_EVIDENCE_REVIEW_NOT_INDEPENDENT")
    if not _SHA256.fullmatch(transport.authority_digest):
        raise ValueError("AUTHORITY_EVIDENCE_AUTHORITY_DIGEST_INVALID")
    if digest_text(transport.source_patch) != transport.source_patch_digest:
        raise ValueError("AUTHORITY_EVIDENCE_PATCH_DIGEST_MISMATCH")
    if not transport.source_patch.startswith("diff --git "):
        raise ValueError("AUTHORITY_EVIDENCE_PATCH_FORMAT_INVALID")
    if not transport.evidence_refs or any(
        not ref.startswith("urn:") for ref in transport.evidence_refs
    ):
        raise ValueError("AUTHORITY_EVIDENCE_REFERENCE_MISSING")
    artifact_digests = [artifact.artifact_digest for artifact in transport.artifacts]
    if not transport.artifacts or any(not _SHA256.fullmatch(item) for item in artifact_digests):
        raise ValueError("AUTHORITY_EVIDENCE_ARTIFACT_DIGEST_INVALID")
    if len(set(artifact_digests)) != len(artifact_digests):
        raise ValueError("AUTHORITY_EVIDENCE_ARTIFACT_DIGEST_DUPLICATE")
    bound_values = (
        transport.authority_digest,
        transport.base_head,
        transport.producer_id,
        *artifact_digests,
        *transport.evidence_refs,
    )
    if any(item not in transport.source_patch for item in bound_values):
        raise ValueError("AUTHORITY_EVIDENCE_BINDING_INCOMPLETE")
    required_terms = (
        transport.obligation_id,
        "ValidationExecution",
        "ValidationResult",
        "ValidationEvidence",
        "executesValidation",
        "producesValidationResult",
        "entersEvidenceLifecycleAs",
        "applicableToObligation",
    )
    if any(term not in transport.source_patch for term in required_terms):
        raise ValueError("AUTHORITY_EVIDENCE_LIFECYCLE_INCOMPLETE")
    if "urn:usf-factory:ontology:ValidationExecutionReceipt" in transport.source_patch:
        raise ValueError("FACTORY_RECEIPT_IS_NOT_AUTHORITY_EVIDENCE")
    for artifact in transport.artifacts:
        if not artifact.locator.startswith("cas:sha256:"):
            raise ValueError("AUTHORITY_EVIDENCE_ARTIFACT_LOCATOR_NOT_IMMUTABLE")
        try:
            artifact_bytes = store.cas_get(artifact.locator)  # type: ignore[attr-defined]
        except Exception as exc:
            raise ValueError("AUTHORITY_EVIDENCE_ARTIFACT_UNAVAILABLE") from exc
        if (
            digest_bytes(artifact_bytes) != artifact.artifact_digest
            or len(artifact_bytes) != artifact.byte_size
        ):
            raise ValueError("AUTHORITY_EVIDENCE_ARTIFACT_UNVERIFIED")

    attestations: list[AuthorityEvidenceAttestation] = []
    for ref, expected_role in (
        (transport.producer_attestation_ref, "producer"),
        (transport.reviewer_attestation_ref, "reviewer"),
    ):
        try:
            raw = store.cas_get(ref)  # type: ignore[attr-defined]
            attestation = AuthorityEvidenceAttestation.model_validate(json.loads(raw))
        except Exception as exc:
            raise ValueError("AUTHORITY_EVIDENCE_ATTESTATION_UNAVAILABLE") from exc
        if attestation.role != expected_role or not attestation.accepted:
            raise ValueError("AUTHORITY_EVIDENCE_ATTESTATION_INVALID")
        attestations.append(attestation)
    producer, reviewer = attestations
    expected_common = {
        "obligation_id": transport.obligation_id,
        "base_head": transport.base_head,
        "authority_digest": transport.authority_digest,
        "source_patch_digest": transport.source_patch_digest,
        "artifact_digests": sorted(artifact_digests),
    }
    for attestation in attestations:
        actual = {
            "obligation_id": attestation.obligation_id,
            "base_head": attestation.base_head,
            "authority_digest": attestation.authority_digest,
            "source_patch_digest": attestation.source_patch_digest,
            "artifact_digests": sorted(attestation.artifact_digests),
        }
        if actual != expected_common:
            raise ValueError("AUTHORITY_EVIDENCE_ATTESTATION_BINDING_MISMATCH")
    if (
        producer.identity != transport.producer_id
        or producer.provider_id != transport.producer_provider_id
        or reviewer.identity != transport.reviewer_id
        or reviewer.provider_id != transport.reviewer_provider_id
    ):
        raise ValueError("AUTHORITY_EVIDENCE_ATTESTATION_IDENTITY_MISMATCH")


def execute_validation_receipt(
    ctx: RuntimeContext,
    *,
    obligation_id: str,
    subject: str,
    clone_path: Path,
    base_head: str,
    authority_digest: str,
    runner: CommandRunner | None = None,
    env: dict[str, str] | None = None,
) -> FactoryValidationReceipt:
    """Run the deterministic suite and record a factory-local observation.

    Fail-closed: any non-zero step yields ``all_passed=False``.  The return value
    never asserts admission, freshness, integrity or authority lifecycle state.
    """
    runner = runner or SubprocessRunner()
    env = dict(env) if env is not None else restricted_subprocess_environment(github=False)
    checks: dict[str, bool] = {}
    detail: dict[str, str] = {}

    ci: CommandResult = runner.run(
        list(_SUITE_INSTALL), cwd=str(clone_path), env=env, timeout=1800.0
    )
    checks["install"] = ci.ok
    detail["install"] = (ci.err or ci.out)[-300:]

    passing = failing = 0
    if ci.ok:
        tr: CommandResult = runner.run(
            list(_SUITE_TEST), cwd=str(clone_path), env=env, timeout=1800.0
        )
        checks["deterministic-suite"] = tr.ok
        detail["deterministic-suite"] = (tr.err or tr.out)[-300:]
        text = f"{tr.out}\n{tr.err}"
        pm, fm = _PASS_RE.search(text), _FAIL_RE.search(text)
        passing = int(pm.group(1)) if pm else 0
        failing = int(fm.group(1)) if fm else (0 if tr.ok else 1)
    else:
        checks["deterministic-suite"] = False
        detail["deterministic-suite"] = "install failed; suite not run"
        failing = 1

    all_passed = all(checks.values()) and failing == 0
    return FactoryValidationReceipt(
        obligation_id=obligation_id,
        subject=subject,
        base_head=base_head,
        authority_digest=authority_digest,
        checks=checks,
        all_passed=all_passed,
        passing_count=passing,
        failing_count=failing,
        detail=detail,
        produced_at=utc_now_iso(),
    )


def compact_receipt_rdf(receipt: FactoryValidationReceipt) -> str:
    """Deterministic Turtle projection of the non-authoritative factory receipt."""

    subj = f"urn:usf-factory:validationreceipt:{receipt.receipt_id}"
    lines = [
        "@prefix factory: <urn:usf-factory:ontology:> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        "",
        f"<{subj}> a factory:ValidationExecutionReceipt ;",
        f'    factory:observedObligation "{receipt.obligation_id}" ;',
        f'    factory:observedSubject "{receipt.subject}" ;',
        f'    factory:repositoryHead "{receipt.base_head}" ;',
        f'    factory:observedAuthorityDigest "{receipt.authority_digest}" ;',
        f'    factory:allChecksPassed "{str(receipt.all_passed).lower()}"^^xsd:boolean ;',
        f'    factory:passingCount "{receipt.passing_count}"^^xsd:integer ;',
        f'    factory:failingCount "{receipt.failing_count}"^^xsd:integer ;',
    ]
    for name in sorted(receipt.checks):
        lines.append(f'    factory:check "{name}={str(receipt.checks[name]).lower()}" ;')
    lines.append(f'    factory:receiptId "{receipt.receipt_id}" .')
    return "\n".join(lines) + "\n"
