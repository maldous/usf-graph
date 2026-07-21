"""Worker execution (DESIGN Phase 9).

Each packet runs in a fresh, disposable clone created from the factory-owned
mirror (never /usf). Workers receive only stable instructions, packet JSON,
relevant source ranges, permitted tools, acceptance criteria, and a result
schema. Workers may produce a patch + evidence candidate; they may NOT write to
/usf, push, merge, publish, or declare completion — this is enforced
deterministically by the sandbox, not by trusting the model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from .canonical import digest_text
from .clock import utc_now_iso
from .enums import FailureClass, PacketResultStatus
from .isolation import RepoIsolation
from .models import AgentProfile, Packet, PacketResult
from .sandbox import scan_secrets, validate_patch_scope

WORKER_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["COMPLETED", "FAILED", "HUMAN_DECISION_REQUIRED"]},
        "patch": {"type": "string"},
        "changed_paths": {"type": "array", "items": {"type": "string"}},
        "semantic_subjects_changed": {"type": "array", "items": {"type": "string"}},
        "tests_run": {"type": "array", "items": {"type": "string"}},
        "evidence_produced": {"type": "array", "items": {"type": "string"}},
        "obligations_closed": {"type": "array", "items": {"type": "string"}},
        "obligations_discovered": {"type": "array", "items": {"type": "string"}},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["status"],
    "additionalProperties": True,
}


def build_worker_instructions(packet: Packet) -> str:
    """Stable instruction prefix + compact packet JSON (never a transcript)."""
    prefix = (
        "You are a USF factory worker operating in an ISOLATED disposable clone. "
        "You may edit only files within the packet write scope. You may NOT push, "
        "merge, fetch, access the network, read secrets, write outside scope, or "
        "declare programme completion. Return ONLY JSON matching the result schema, "
        "including a git unified diff in `patch` limited to the write scope. If a "
        "human decision is required, return status HUMAN_DECISION_REQUIRED."
    )
    packet_json = json.dumps(
        {
            "packetId": packet.packet_id,
            "objective": packet.objective,
            "taskClass": packet.task_class,
            "semanticSubjects": packet.semantic_subjects,
            "readPaths": packet.read_paths,
            "writePaths": packet.write_paths,
            "acceptanceCriteria": packet.acceptance_criteria,
            "permittedTools": packet.permitted_tools,
            "authorityDigest": packet.authority_digest,
            "baseHead": packet.base_head,
        },
        sort_keys=True,
    )
    return f"{prefix}\n\nPACKET:\n{packet_json}"


class Worker(Protocol):
    async def execute(
        self, packet: Packet, workspace: Path, agent: AgentProfile
    ) -> PacketResult: ...


class DryRunWorker:
    """Produces a non-mutating result. Used by observe / plan-only / safe cycles.

    It creates no patch and writes nothing, so a safe cycle never mutates /usf and
    never incurs billable inference.
    """

    async def execute(self, packet: Packet, workspace: Path, agent: AgentProfile) -> PacketResult:
        status = (
            PacketResultStatus.HUMAN_DECISION_REQUIRED
            if packet.human_decision_required
            else PacketResultStatus.SKIPPED
        )
        return PacketResult(
            packet_id=packet.packet_id,
            status=status,
            agent_profile_id=agent.profile_id,
            actual_provider="dry-run",
            actual_model="dry-run",
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            patch_digest=None,
            changed_paths=[],
            uncertainties=["dry-run: no execution performed"],
            produced_at=utc_now_iso(),
        )


class AiWorker:
    """Runs a packet through a qualified agent, enforcing the sandbox on output.

    Billable/egress-gated by the caller. The produced patch is validated against
    the write scope and scanned for secrets BEFORE it is accepted; a violation
    yields a SCOPE_VIOLATION result rather than a patch.
    """

    def __init__(self, invoke, isolation: RepoIsolation) -> None:
        self._invoke = invoke  # async callable(AgentRequest)->AgentResponse
        self._iso = isolation

    async def execute(self, packet: Packet, workspace: Path, agent: AgentProfile) -> PacketResult:
        from .models import AgentRequest

        req = AgentRequest(
            agent_profile_id=agent.profile_id,
            packet_id=packet.packet_id,
            instructions=build_worker_instructions(packet),
            packet_json={"packetId": packet.packet_id},
            permitted_tools=packet.permitted_tools,
            result_schema=WORKER_RESULT_SCHEMA,
        )
        try:
            resp = await self._invoke(req)
        except Exception as exc:
            return self._failed(packet, agent, FailureClass.ADAPTER_ERROR, str(exc))

        data = _parse_result(resp.output_text) or {}
        patch = str(data.get("patch", ""))

        # Deterministic sandbox enforcement (never trust the model).
        if patch:
            violations = validate_patch_scope(patch, packet.write_paths)
            leaks = scan_secrets(patch)
            if violations or leaks:
                return PacketResult(
                    packet_id=packet.packet_id,
                    status=PacketResultStatus.FAILED,
                    agent_profile_id=agent.profile_id,
                    actual_provider=resp.actual_provider,
                    actual_model=resp.actual_model,
                    base_head=packet.base_head,
                    snapshot_id=packet.snapshot_id,
                    scope_violation=True,
                    failure_class=FailureClass.SCOPE_VIOLATION,
                    failure_detail="; ".join(violations + leaks)[:500],
                    produced_at=utc_now_iso(),
                )

        status_str = str(data.get("status", "COMPLETED"))
        try:
            status = PacketResultStatus(status_str)
        except ValueError:
            status = PacketResultStatus.COMPLETED

        patch_digest = digest_text(patch) if patch else None
        return PacketResult(
            packet_id=packet.packet_id,
            status=status,
            agent_profile_id=agent.profile_id,
            actual_provider=resp.actual_provider,
            actual_model=resp.actual_model,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            patch_digest=patch_digest,
            changed_paths=validate_and_list(patch),
            semantic_subjects_changed=list(data.get("semantic_subjects_changed", [])),
            tests_run=list(data.get("tests_run", [])),
            evidence_produced=list(data.get("evidence_produced", [])),
            obligations_closed=list(data.get("obligations_closed", [])),
            obligations_discovered=list(data.get("obligations_discovered", [])),
            uncertainties=list(data.get("uncertainties", [])),
            produced_at=utc_now_iso(),
        )

    def _failed(
        self, packet: Packet, agent: AgentProfile, fc: FailureClass, detail: str
    ) -> PacketResult:
        return PacketResult(
            packet_id=packet.packet_id,
            status=PacketResultStatus.FAILED,
            agent_profile_id=agent.profile_id,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            failure_class=fc,
            failure_detail=detail[:500],
            produced_at=utc_now_iso(),
        )


def validate_and_list(patch: str) -> list[str]:
    from .sandbox import parse_unified_diff_paths

    return parse_unified_diff_paths(patch) if patch else []


def _parse_result(text: str) -> dict[str, Any] | None:
    import re

    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                return None
    return None
