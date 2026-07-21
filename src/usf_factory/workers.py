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

import jsonschema

from .canonical import digest_text
from .clock import utc_now_iso
from .enums import FailureClass, PacketResultStatus
from .isolation import RepoIsolation
from .models import AgentProfile, Packet, PacketResult
from .sandbox import scan_secrets, validate_patch_scope

# Strict result contract: unknown fields are rejected, status is a closed enum.
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
        "validation_receipts": {"type": "array", "items": {"type": "object"}},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["status"],
    "additionalProperties": False,
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

    def __init__(self, invoke, isolation: RepoIsolation, store=None) -> None:
        self._invoke = invoke  # async callable(AgentRequest)->AgentResponse
        self._iso = isolation
        self._store = store  # optional Store for CAS patch persistence

    async def execute(self, packet: Packet, workspace: Path, agent: AgentProfile) -> PacketResult:
        from .models import AgentRequest

        req = AgentRequest(
            agent_profile_id=agent.profile_id,
            packet_id=packet.packet_id,
            instructions=build_worker_instructions(packet),
            provider_id=agent.provider_id,
            requested_model_id=agent.requested_model_id,
            adapter_id=agent.adapter,
            tool_profile_id=agent.tool_profile,
            prompt_version=agent.prompt_version,
            packet_json={"packetId": packet.packet_id},
            permitted_tools=packet.permitted_tools,
            result_schema=WORKER_RESULT_SCHEMA,
        )
        try:
            resp = await self._invoke(req)
        except Exception as exc:
            return self._failed(packet, agent, FailureClass.ADAPTER_ERROR, str(exc))

        # Strict, fail-closed parsing. Invalid/absent JSON or an unknown/missing
        # status is a FAILURE — never a silent COMPLETED.
        data = _parse_result(resp.output_text)
        if data is None:
            return self._failed(
                packet, agent, FailureClass.WORKER_ERROR, "result was not valid JSON"
            )
        try:
            jsonschema.validate(data, WORKER_RESULT_SCHEMA)
        except jsonschema.ValidationError as exc:
            return self._failed(
                packet, agent, FailureClass.WORKER_ERROR, f"result schema violation: {exc.message}"
            )

        try:
            status = PacketResultStatus(str(data["status"]))
        except (KeyError, ValueError):
            return self._failed(
                packet, agent, FailureClass.WORKER_ERROR, "missing or unknown status"
            )

        patch = str(data.get("patch", ""))

        # Deterministic sandbox enforcement (never trust the model).
        if patch:
            violations = validate_patch_scope(patch, packet.write_paths)
            leaks = scan_secrets(patch)
            if violations or leaks:
                return self._failed(
                    packet,
                    agent,
                    FailureClass.SCOPE_VIOLATION,
                    "; ".join(violations + leaks),
                    scope_violation=True,
                    actual_provider=resp.actual_provider,
                    actual_model=resp.actual_model,
                )

        # A mutating packet claiming COMPLETED must produce a real patch touching
        # at least one in-scope path. No patch => not a durable completion.
        changed = validate_and_list(patch)
        if status is PacketResultStatus.COMPLETED and packet.write_paths and not changed:
            return self._failed(
                packet,
                agent,
                FailureClass.WORKER_ERROR,
                "mutating packet completed without a patch/changed paths",
                actual_provider=resp.actual_provider,
                actual_model=resp.actual_model,
            )

        # Persist the exact patch bytes in CAS (attribution + replay).
        patch_ref = None
        patch_digest = None
        if patch and self._store is not None:
            patch_ref = self._store.cas_put_text(patch)
            patch_digest = patch_ref.split("cas:", 1)[-1]
        elif patch:
            patch_digest = digest_text(patch)

        return PacketResult(
            packet_id=packet.packet_id,
            status=status,
            agent_profile_id=agent.profile_id,
            actual_provider=resp.actual_provider,
            actual_model=resp.actual_model,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            patch_digest=patch_digest,
            patch_ref=patch_ref,
            changed_paths=changed,
            semantic_subjects_changed=list(data.get("semantic_subjects_changed", [])),
            tests_run=list(data.get("tests_run", [])),
            evidence_produced=list(data.get("evidence_produced", [])),
            obligations_closed=list(data.get("obligations_closed", [])),
            obligations_discovered=list(data.get("obligations_discovered", [])),
            uncertainties=list(data.get("uncertainties", [])),
            produced_at=utc_now_iso(),
        )

    def _failed(
        self,
        packet: Packet,
        agent: AgentProfile,
        fc: FailureClass,
        detail: str,
        *,
        scope_violation: bool = False,
        actual_provider: str | None = None,
        actual_model: str | None = None,
    ) -> PacketResult:
        return PacketResult(
            packet_id=packet.packet_id,
            status=PacketResultStatus.FAILED,
            agent_profile_id=agent.profile_id,
            actual_provider=actual_provider,
            actual_model=actual_model,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            scope_violation=scope_violation,
            failure_class=fc,
            failure_detail=detail[:500],
            produced_at=utc_now_iso(),
        )


def validate_and_list(patch: str) -> list[str]:
    from .sandbox import parse_unified_diff_paths

    return parse_unified_diff_paths(patch) if patch else []


def _parse_result(text: str) -> dict[str, Any] | None:
    """Strict parse of a worker result.

    The entire output (after stripping a single markdown fence) must be one JSON
    object. There is NO regex "find any JSON in the prose" recovery — that path
    is a false-success risk and is deliberately absent.
    """
    import re

    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
