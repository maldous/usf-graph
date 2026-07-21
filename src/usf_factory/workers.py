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

        # A read-only packet claiming COMPLETED must produce durable evidence;
        # its structured result is persisted to CAS as the analysis artifact.
        # (Without a store the artifact cannot be durable, so analysis_ref stays
        # None and deterministic qualification rejects the completion.)
        analysis_ref = None
        if status is PacketResultStatus.COMPLETED and not packet.write_paths:
            if not data.get("evidence_produced"):
                return self._failed(
                    packet,
                    agent,
                    FailureClass.WORKER_ERROR,
                    "read-only completion without evidence_produced (durable analysis required)",
                    actual_provider=resp.actual_provider,
                    actual_model=resp.actual_model,
                )
            if self._store is not None:
                analysis_ref = self._store.cas_put_text(json.dumps(data, sort_keys=True))

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
            analysis_ref=analysis_ref,
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


class BrokeredWorker:
    """Runs a packet through the bounded tool broker in a real workspace, then the
    ORCHESTRATOR derives the exact patch from git (never trusts a model-reported
    diff). The model gets no OS/network access — only broker tools.

    ``mutating`` False => shadow (edits validated, not applied). Billable/live
    model access is the caller's responsibility (gated).
    """

    def __init__(
        self,
        chat_fn,
        store=None,
        *,
        mutating: bool = True,
        max_turns: int = 12,
        validation_runner=None,
        source_content_allowed: bool = True,
    ) -> None:
        self._chat = chat_fn
        self._store = store
        self._mutating = mutating
        self._max_turns = max_turns
        self._validation_runner = validation_runner
        self._source_content_allowed = source_content_allowed

    async def execute(self, packet: Packet, workspace: Path, agent: AgentProfile) -> PacketResult:
        import subprocess

        from .agent_runtime import GenericToolLoop, ToolBroker

        mutating = self._mutating and bool(packet.write_paths)
        broker = ToolBroker(
            workspace=workspace,
            packet=packet,
            mutating=mutating,
            validation_runner=self._validation_runner,
            source_content_allowed=self._source_content_allowed,
        )
        try:
            loop_res = await GenericToolLoop(self._chat, max_turns=self._max_turns).run(
                packet, broker
            )
        except Exception as exc:
            return self._failed(packet, agent, FailureClass.ADAPTER_ERROR, str(exc))

        if broker.finished is None:
            return self._failed(
                packet, agent, FailureClass.WORKER_ERROR, "loop ended without finish_packet"
            )
        status_str = str(broker.finished.get("status", ""))
        try:
            status = PacketResultStatus(status_str)
        except ValueError:
            return self._failed(packet, agent, FailureClass.WORKER_ERROR, "unknown finish status")

        # A read-only packet claiming COMPLETED must carry DURABLE analysis
        # evidence (findings + criteria_results persisted to CAS). A bare
        # "COMPLETED" with no work product can never be accepted or rewarded.
        analysis_ref: str | None = None
        if status is PacketResultStatus.COMPLETED and not packet.write_paths:
            findings = [
                str(f).strip() for f in broker.finished.get("findings") or [] if str(f).strip()
            ]
            criteria = broker.finished.get("criteria_results") or {}
            if not findings or (packet.acceptance_criteria and not criteria):
                return self._failed(
                    packet,
                    agent,
                    FailureClass.WORKER_ERROR,
                    "read-only completion without durable analysis evidence "
                    "(findings + criteria_results required)",
                )
            if self._store is None:
                return self._failed(
                    packet,
                    agent,
                    FailureClass.WORKER_ERROR,
                    "no store available to persist the analysis artifact (fail closed)",
                )
            analysis_ref = self._store.cas_put_text(
                json.dumps(
                    {
                        "packet_id": packet.packet_id,
                        "findings": findings,
                        "criteria_results": criteria,
                        "uncertainties": list(broker.finished.get("uncertainties", [])),
                        "transcript_digest": loop_res.transcript_digest,
                        "turns": loop_res.turns,
                    },
                    sort_keys=True,
                )
            )

        # Orchestrator-derived patch: stage everything and diff against HEAD.
        patch = ""
        changed: list[str] = []
        if mutating:
            subprocess.run(
                ["git", "-C", str(workspace), "add", "-A"], capture_output=True, text=True
            )
            patch = subprocess.run(
                ["git", "-C", str(workspace), "diff", "--cached", "HEAD"],
                capture_output=True,
                text=True,
            ).stdout
            changed = subprocess.run(
                ["git", "-C", str(workspace), "diff", "--cached", "--name-only", "HEAD"],
                capture_output=True,
                text=True,
            ).stdout.split()

        # Deterministic scope + secret enforcement on the ACTUAL diff.
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
                )
        if status is PacketResultStatus.COMPLETED and packet.write_paths and not changed:
            return self._failed(
                packet,
                agent,
                FailureClass.WORKER_ERROR,
                "mutating packet completed without any workspace change",
            )

        patch_ref = self._store.cas_put_text(patch) if (patch and self._store is not None) else None
        patch_digest = digest_text(patch) if patch else None
        return PacketResult(
            packet_id=packet.packet_id,
            status=status,
            agent_profile_id=agent.profile_id,
            actual_provider=agent.provider_id,
            actual_model=agent.requested_model_id,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            patch_digest=patch_digest,
            patch_ref=patch_ref,
            analysis_ref=analysis_ref,
            changed_paths=sorted(changed),
            evidence_produced=[analysis_ref] if analysis_ref else [],
            uncertainties=list(broker.finished.get("uncertainties", [])),
            produced_at=utc_now_iso(),
        )

    def _failed(self, packet, agent, fc, detail, *, scope_violation=False):
        return PacketResult(
            packet_id=packet.packet_id,
            status=PacketResultStatus.FAILED,
            agent_profile_id=agent.profile_id,
            base_head=packet.base_head,
            snapshot_id=packet.snapshot_id,
            scope_violation=scope_violation,
            failure_class=fc,
            failure_detail=str(detail)[:500],
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
