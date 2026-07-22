"""Validation-evidence execution + compact evidence RDF (build task §2-§3).

Some authority gaps are closed not by a source change but by EXECUTING the
governed deterministic validation and admitting the resulting evidence — e.g. the
``missing-current-passing-validation`` obligation. This module runs the real
usf-graph deterministic suite in a disposable clone at a base commit, records a
content-addressed :class:`ValidationEvidenceReceipt` (per-check pass/fail +
digests), and serialises a compact RDF/Turtle evidence artifact from it.

It performs NO publication and NO mutation of ``/usf``; it only produces evidence
that the delivery coordinator then carries through the protected lifecycle. The
receipt is deterministic: an independent re-execution over the same commit yields
the same checks, which is what makes independent review of an evidence delivery a
genuine re-validation rather than a judgement call.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import Field

from .canonical import stable_id
from .clock import utc_now_iso
from .context import RuntimeContext
from .github_delivery import CommandResult, CommandRunner, SubprocessRunner
from .models import FactoryModel

# The canonical deterministic suite entry point in usf-graph (package.json).
_SUITE_INSTALL = ("npm", "ci")
_SUITE_TEST = ("npm", "test")
# Extract a "N passing" / "N failing" tally from common test-runner output.
_PASS_RE = re.compile(r"(\d+)\s+pass", re.I)
_FAIL_RE = re.compile(r"(\d+)\s+fail", re.I)


class ValidationEvidenceReceipt(FactoryModel):
    """Content-addressed evidence that the deterministic validation passed at a
    specific commit against a specific authority digest."""

    obligation_id: str
    subject: str = ""
    base_head: str
    authority_digest: str = ""
    checks: dict[str, bool] = Field(default_factory=dict)
    all_passed: bool = False
    passing_count: int = 0
    failing_count: int = 0
    detail: dict[str, str] = Field(default_factory=dict)
    produced_at: str = ""

    _volatile_fields = frozenset({"produced_at"})

    @property
    def evidence_id(self) -> str:
        return stable_id("vev", self.content_dict())


def execute_validation_evidence(
    ctx: RuntimeContext,
    *,
    obligation_id: str,
    subject: str,
    clone_path: Path,
    base_head: str,
    authority_digest: str,
    runner: CommandRunner | None = None,
    env: dict[str, str] | None = None,
) -> ValidationEvidenceReceipt:
    """Run the deterministic suite in ``clone_path`` (a clone already checked out at
    ``base_head``) and record the evidence. Fail-closed: any non-zero step yields
    ``all_passed=False``; nothing is fabricated."""
    runner = runner or SubprocessRunner()
    checks: dict[str, bool] = {}
    detail: dict[str, str] = {}

    ci: CommandResult = runner.run(list(_SUITE_INSTALL), cwd=str(clone_path), env=env, timeout=1800.0)
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
    return ValidationEvidenceReceipt(
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


def compact_evidence_rdf(receipt: ValidationEvidenceReceipt) -> str:
    """A compact, deterministic RDF/Turtle serialisation of the evidence receipt.
    Blank-node-free and ordering-stable so the same receipt yields byte-identical
    Turtle (content-addressable)."""
    subj = f"urn:usf:validationevidence:{receipt.evidence_id}"
    lines = [
        "@prefix usf: <urn:usf:> .",
        "@prefix ev: <urn:usf:evidence#> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        "",
        f"<{subj}> a ev:ValidationEvidence ;",
        f'    ev:obligation "{receipt.obligation_id}" ;',
        f'    ev:subject "{receipt.subject}" ;',
        f'    ev:baseHead "{receipt.base_head}" ;',
        f'    ev:authorityDigest "{receipt.authority_digest}" ;',
        f'    ev:allPassed "{str(receipt.all_passed).lower()}"^^xsd:boolean ;',
        f'    ev:passingCount "{receipt.passing_count}"^^xsd:integer ;',
        f'    ev:failingCount "{receipt.failing_count}"^^xsd:integer ;',
    ]
    for name in sorted(receipt.checks):
        lines.append(f'    ev:check "{name}={str(receipt.checks[name]).lower()}" ;')
    lines.append(f'    ev:evidenceId "{receipt.evidence_id}" .')
    return "\n".join(lines) + "\n"


def evidence_files(receipt: ValidationEvidenceReceipt) -> dict[str, str]:
    """The compact evidence artifact(s) to deliver into the usf-graph clone."""
    rel = f"evidence/validation/{receipt.obligation_id.replace(':', '_')}.ttl"
    return {rel: compact_evidence_rdf(receipt)}
