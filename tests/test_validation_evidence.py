"""Spec §2/§3/§11 — validation-evidence execution, compact RDF, and delivery."""

from __future__ import annotations

import pytest

from test_delivery_coordinator import EXPECTED_DIGEST, FakeGitHub, FakePublisher, _authz
from usf_factory.delivery_coordinator import DeliveryCoordinator
from usf_factory.enums import DeliveryState
from usf_factory.github_delivery import CommandResult
from usf_factory.validation_evidence import (
    compact_evidence_rdf,
    evidence_files,
    execute_validation_evidence,
)

SUBJECT = "urn:usf:validationobligation:repositoryexternalartefactmaterialisation"


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


@pytest.mark.unit
def test_execute_validation_evidence_pass(ctx, tmp_usf):
    r = FakeRunner()
    rec = execute_validation_evidence(
        ctx, obligation_id=SUBJECT, subject=SUBJECT, clone_path=tmp_usf,
        base_head="base000", authority_digest=EXPECTED_DIGEST, runner=r,
    )
    assert rec.all_passed is True
    assert rec.checks == {"install": True, "deterministic-suite": True}
    assert rec.passing_count == 42 and rec.failing_count == 0
    assert rec.evidence_id.startswith("vev-")


@pytest.mark.adversarial
def test_execute_validation_evidence_install_failure_fails_closed(ctx, tmp_usf):
    rec = execute_validation_evidence(
        ctx, obligation_id=SUBJECT, subject=SUBJECT, clone_path=tmp_usf,
        base_head="base000", authority_digest=EXPECTED_DIGEST,
        runner=FakeRunner(install_ok=False),
    )
    assert rec.all_passed is False and rec.checks["deterministic-suite"] is False


@pytest.mark.unit
def test_compact_evidence_rdf_is_deterministic(ctx, tmp_usf):
    rec = execute_validation_evidence(
        ctx, obligation_id=SUBJECT, subject=SUBJECT, clone_path=tmp_usf,
        base_head="base000", authority_digest=EXPECTED_DIGEST, runner=FakeRunner(),
    )
    a = compact_evidence_rdf(rec)
    b = compact_evidence_rdf(rec)
    assert a == b  # byte-identical (content-addressable)
    assert "ev:ValidationEvidence" in a and SUBJECT in a
    assert next(iter(evidence_files(rec))).startswith("evidence/validation/")


@pytest.mark.e2e
def test_deliver_validation_evidence_full_lifecycle(ctx, tmp_usf):
    ctx.run_authorization = _authz()
    gh, pub = FakeGitHub(), FakePublisher(live_digest=EXPECTED_DIGEST)
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver_validation_evidence(
        obligation_id=SUBJECT,
        subject=SUBJECT,
        base_head="base000",
        authority_digest=EXPECTED_DIGEST,
        runner=FakeRunner(),
    )
    assert rec.state == DeliveryState.COMPLETE.value
    assert rec.remediation_kind == "VALIDATION_EVIDENCE"
    assert "write_files" in gh.calls and "apply" not in gh.calls  # evidence record, not a diff
    # The evidence receipt was persisted (content-addressed).
    ev = list(ctx.store.items("validation_evidence"))
    assert ev and ev[0][1]["obligation_id"] == SUBJECT


@pytest.mark.adversarial
def test_failing_suite_blocks_evidence_delivery(ctx, tmp_usf):
    ctx.run_authorization = _authz()
    gh, pub = FakeGitHub(), FakePublisher(live_digest=EXPECTED_DIGEST)
    coord = DeliveryCoordinator(ctx, github=gh, publisher=pub)
    rec = coord.deliver_validation_evidence(
        obligation_id=SUBJECT, subject=SUBJECT, base_head="base000",
        authority_digest=EXPECTED_DIGEST, runner=FakeRunner(test_ok=False),
    )
    assert rec.state == DeliveryState.BLOCKED.value  # no evidence => nothing delivered
    assert gh.pushed == 0 and pub.published == 0
