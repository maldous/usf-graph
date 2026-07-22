"""Content-addressed assurance closure for protected delivery.

The delivery coordinator never accepts caller booleans as proof.  It admits a
wave only after reloading the canonical patch, validation receipt, review
receipt and bundle bytes from CAS and verifying every cross-binding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json, content_digest, digest_bytes
from .enums import RemediationKind, Risk
from .models import ActionableGapIdentity, AssuranceBundle, ValidationReceipt, WaveReview


@dataclass(frozen=True)
class VerifiedAssurance:
    bundle: AssuranceBundle
    validation: ValidationReceipt
    review: WaveReview
    patch_bytes: bytes


def _digest_for_ref(ref: str) -> str:
    if not ref.startswith("cas:sha256:") or len(ref) != 75:
        raise ValueError("ASSURANCE_CAS_REFERENCE_INVALID")
    return ref.removeprefix("cas:")


def _load_json(store: Any, ref: str, error_code: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = store.cas_get(ref)
        value = json.loads(data)
    except Exception as exc:
        raise ValueError(error_code) from exc
    if not isinstance(value, dict):
        raise ValueError(error_code)
    if digest_bytes(data) != _digest_for_ref(ref):
        raise ValueError(error_code)
    return value, data


def persist_assurance_bundle(
    store: Any,
    *,
    set_id: str,
    obligation_ids: list[str],
    gap_identities: list[ActionableGapIdentity],
    remediation_kind: RemediationKind,
    maximum_risk: Risk,
    repository_base_head: str,
    expected_authority_digest: str,
    patch_ref: str,
    validation: ValidationReceipt,
    review: WaveReview,
    policy_digest: str,
    workforce_snapshot_id: str,
    run_authorization_digest: str,
) -> tuple[str, AssuranceBundle]:
    """Persist exact receipt bytes and the enclosing bundle; return its CAS ref.

    Both receipts must already be schema-v2 and therefore self-validating.  The
    function stores their canonical identity bytes, so later verification is
    independent of mutable record-table projections.
    """

    if validation.schema_version < 2 or review.schema_version < 2:
        raise ValueError("ASSURANCE_RECEIPT_SCHEMA_UNSUPPORTED")
    patch_bytes = store.cas_get(patch_ref)
    patch_digest = digest_bytes(patch_bytes)
    if validation.patch_ref != patch_ref or validation.patch_digest != patch_digest:
        raise ValueError("ASSURANCE_VALIDATION_PATCH_MISMATCH")
    validation_ref = store.cas_put_text(canonical_json(validation.content_dict()))
    review_ref = store.cas_put_text(canonical_json(review.content_dict()))
    bundle = AssuranceBundle(
        schema_version=1,
        set_id=set_id,
        obligation_ids=sorted(set(obligation_ids)),
        gap_identities=[
            {"type": key[0], "subject": key[1]}
            for key in sorted({(gap.type, gap.subject) for gap in gap_identities})
        ],
        remediation_kind=remediation_kind,
        maximum_risk=maximum_risk,
        repository_base_head=repository_base_head,
        expected_authority_digest=expected_authority_digest,
        patch_digest=patch_digest,
        patch_ref=patch_ref,
        validation_receipt_digest=_digest_for_ref(validation_ref),
        validation_receipt_ref=validation_ref,
        review_receipt_digest=_digest_for_ref(review_ref),
        review_receipt_ref=review_ref,
        review_context_digest=review.review_context_digest,
        review_context_ref=review.review_context_ref,
        validation_runner_inventory_digest=validation.runner_inventory_digest,
        toolchain_inventory_digest=validation.toolchain_inventory_digest,
        reviewer_profile_id=str(review.reviewer_profile_id or ""),
        reviewer_provider_id=review.reviewer_provider_id,
        reviewer_actual_model=review.reviewer_actual_model,
        reviewer_admission_digest=review.reviewer_admission_digest,
        reviewer_admission_ref=review.reviewer_admission_ref,
        authoring_identities=sorted(set(review.authoring_identities)),
        authoring_providers=sorted(set(review.authoring_providers)),
        reviewer_independent=review.independence_determined,
        policy_digest=policy_digest,
        workforce_snapshot_id=workforce_snapshot_id,
        run_authorization_digest=run_authorization_digest,
    )
    bundle_ref = store.cas_put_text(canonical_json(bundle.content_dict()))
    return bundle_ref, bundle


def verify_assurance_bundle(
    store: Any,
    *,
    bundle_ref: str,
    bundle_digest: str,
    set_id: str,
    obligation_ids: list[str],
    gap_identities: list[ActionableGapIdentity],
    remediation_kind: RemediationKind,
    maximum_risk: Risk,
    repository_base_head: str,
    expected_authority_digest: str,
    run_authorization_digest: str,
) -> VerifiedAssurance:
    """Reload and cross-check a complete bundle from immutable CAS bytes."""

    bundle_data, _ = _load_json(store, bundle_ref, "ASSURANCE_BUNDLE_BYTES_UNAVAILABLE")
    if bundle_digest != _digest_for_ref(bundle_ref):
        raise ValueError("ASSURANCE_BUNDLE_DIGEST_MISMATCH")
    try:
        bundle = AssuranceBundle.model_validate(bundle_data)
    except Exception as exc:
        raise ValueError("ASSURANCE_BUNDLE_SCHEMA_INVALID") from exc

    expected = {
        "set_id": set_id,
        "obligation_ids": sorted(set(obligation_ids)),
        "gap_identities": [
            ActionableGapIdentity(type=key[0], subject=key[1])
            for key in sorted({(gap.type, gap.subject) for gap in gap_identities})
        ],
        "remediation_kind": remediation_kind,
        "maximum_risk": maximum_risk,
        "repository_base_head": repository_base_head,
        "expected_authority_digest": expected_authority_digest,
        "run_authorization_digest": run_authorization_digest,
    }
    for field, value in expected.items():
        if getattr(bundle, field) != value:
            raise ValueError(f"ASSURANCE_BINDING_MISMATCH:{field}")

    try:
        patch_bytes = store.cas_get(bundle.patch_ref)
    except Exception as exc:
        raise ValueError("ASSURANCE_PATCH_BYTES_UNAVAILABLE") from exc
    if digest_bytes(patch_bytes) != bundle.patch_digest:
        raise ValueError("ASSURANCE_PATCH_DIGEST_MISMATCH")

    validation_data, validation_bytes = _load_json(
        store, bundle.validation_receipt_ref, "ASSURANCE_VALIDATION_RECEIPT_UNAVAILABLE"
    )
    review_data, review_bytes = _load_json(
        store, bundle.review_receipt_ref, "ASSURANCE_REVIEW_RECEIPT_UNAVAILABLE"
    )
    context_data, context_bytes = _load_json(
        store, bundle.review_context_ref, "ASSURANCE_REVIEW_CONTEXT_UNAVAILABLE"
    )
    admission_data, admission_bytes = _load_json(
        store,
        bundle.reviewer_admission_ref,
        "ASSURANCE_REVIEWER_ADMISSION_UNAVAILABLE",
    )
    if digest_bytes(context_bytes) != bundle.review_context_digest:
        raise ValueError("ASSURANCE_REVIEW_CONTEXT_DIGEST_MISMATCH")
    if digest_bytes(validation_bytes) != bundle.validation_receipt_digest:
        raise ValueError("ASSURANCE_VALIDATION_RECEIPT_DIGEST_MISMATCH")
    if digest_bytes(review_bytes) != bundle.review_receipt_digest:
        raise ValueError("ASSURANCE_REVIEW_RECEIPT_DIGEST_MISMATCH")
    if digest_bytes(admission_bytes) != bundle.reviewer_admission_digest:
        raise ValueError("ASSURANCE_REVIEWER_ADMISSION_DIGEST_MISMATCH")
    try:
        validation = ValidationReceipt.model_validate(validation_data)
        review = WaveReview.model_validate(review_data)
    except Exception as exc:
        raise ValueError("ASSURANCE_RECEIPT_SCHEMA_INVALID") from exc
    if validation.schema_version < 2 or review.schema_version < 2:
        raise ValueError("ASSURANCE_RECEIPT_SCHEMA_UNSUPPORTED")
    if not validation.all_passed:
        raise ValueError("ASSURANCE_VALIDATION_NOT_PASSED")
    if not review.approved:
        raise ValueError("ASSURANCE_REVIEW_NOT_APPROVED")
    if content_digest(validation.runner_bindings) != validation.runner_inventory_digest:
        raise ValueError("ASSURANCE_RUNNER_INVENTORY_DIGEST_MISMATCH")
    if content_digest(validation.toolchain_bindings) != validation.toolchain_inventory_digest:
        raise ValueError("ASSURANCE_TOOLCHAIN_INVENTORY_DIGEST_MISMATCH")
    if str(context_data.get("setId") or "") != bundle.set_id:
        raise ValueError("ASSURANCE_REVIEW_CONTEXT_SET_MISMATCH")
    effective_diff = context_data.get("effectiveDiff")
    if (
        not isinstance(effective_diff, str)
        or digest_bytes(effective_diff.encode()) != bundle.patch_digest
    ):
        raise ValueError("ASSURANCE_REVIEW_CONTEXT_PATCH_MISMATCH")

    cross_bindings = {
        "validation.set_id": (validation.set_id, bundle.set_id),
        "validation.patch_digest": (validation.patch_digest, bundle.patch_digest),
        "validation.patch_ref": (validation.patch_ref, bundle.patch_ref),
        "validation.repository_base_head": (
            validation.repository_base_head,
            bundle.repository_base_head,
        ),
        "validation.authority_digest": (
            validation.authority_digest,
            bundle.expected_authority_digest,
        ),
        "validation.runner_inventory_digest": (
            validation.runner_inventory_digest,
            bundle.validation_runner_inventory_digest,
        ),
        "review.set_id": (review.set_id, bundle.set_id),
        "review.patch_digest": (review.patch_digest, bundle.patch_digest),
        "review.validation_receipt_digest": (
            review.validation_receipt_digest,
            bundle.validation_receipt_digest,
        ),
        "review.review_context_digest": (
            review.review_context_digest,
            bundle.review_context_digest,
        ),
        "review.review_context_ref": (review.review_context_ref, bundle.review_context_ref),
        "review.reviewer_profile_id": (
            str(review.reviewer_profile_id or ""),
            bundle.reviewer_profile_id,
        ),
        "review.reviewer_provider_id": (
            review.reviewer_provider_id,
            bundle.reviewer_provider_id,
        ),
        "review.reviewer_actual_model": (
            review.reviewer_actual_model,
            bundle.reviewer_actual_model,
        ),
        "review.reviewer_admission_digest": (
            review.reviewer_admission_digest,
            bundle.reviewer_admission_digest,
        ),
        "review.reviewer_admission_ref": (
            review.reviewer_admission_ref,
            bundle.reviewer_admission_ref,
        ),
        "review.authoring_identities": (
            sorted(set(review.authoring_identities)),
            bundle.authoring_identities,
        ),
        "review.authoring_providers": (
            sorted(set(review.authoring_providers)),
            bundle.authoring_providers,
        ),
    }
    for field, (actual, wanted) in cross_bindings.items():
        if actual != wanted:
            raise ValueError(f"ASSURANCE_CROSS_BINDING_MISMATCH:{field}")
    if review.reviewer_profile_id in review.authoring_identities:
        raise ValueError("ASSURANCE_REVIEWER_IDENTITY_NOT_INDEPENDENT")
    if review.reviewer_provider_id in review.authoring_providers:
        raise ValueError("ASSURANCE_REVIEWER_NOT_INDEPENDENT")
    if review.reviewer_profile_id == "deterministic-review-not-required":
        if (
            admission_data.get("kind") != "review-not-required"
            or admission_data.get("policy_digest") != bundle.policy_digest
        ):
            raise ValueError("ASSURANCE_REVIEW_POLICY_ADMISSION_INVALID")
    elif admission_data.get(
        "agent_profile_id"
    ) != review.reviewer_profile_id or "reviewer" not in set(admission_data.get("roles") or []):
        raise ValueError("ASSURANCE_REVIEWER_ADMISSION_INVALID")
    return VerifiedAssurance(bundle, validation, review, patch_bytes)
