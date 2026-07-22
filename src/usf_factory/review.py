"""Independent wave review (DESIGN Phase 12).

Review is advisory and risk-discovering — it is NEVER proof. Deterministic
validation remains authoritative. Reviewers should come from a different provider
than the integrator to reduce correlated failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .clock import utc_now_iso
from .models import WavePatch, WaveReview

WAVE_REVIEW_QUESTIONS = (
    "Did one packet invalidate another?",
    "Did the integration reopen a previously closed obligation?",
    "Were requirements broadened without authority?",
    "Were completion claims introduced without evidence?",
    "Were generated artifacts changed directly?",
    "Was backward compatibility preserved?",
    "Are new negative tests sufficient?",
)


class WaveReviewer(Protocol):
    async def review(
        self, set_id: str, wave: WavePatch | None, bundle: Any | None = None
    ) -> WaveReview: ...


class NoopReviewer:
    """Advisory reviewer that records no findings (e.g. no wave patch to review).
    Never APPROVES a wave — a real reviewer is required to approve a mutation."""

    async def review(
        self, set_id: str, wave: WavePatch | None, bundle: Any | None = None
    ) -> WaveReview:
        findings = (
            [] if wave is None else ["no automated reviewer configured; manual review advised"]
        )
        return WaveReview(
            set_id=set_id,
            reviewer_profile_id="noop-reviewer",
            advisory=True,
            approved=wave
            is None,  # nothing to review => trivially fine; a real wave is not approved
            findings=findings,
            risk_flags=[],
            reviewed_at=utc_now_iso(),
        )


@dataclass
class ReviewContextBundle:
    """Bounded, content-addressed review context. The reviewer receives the ACTUAL
    effective diff and evidence — never merely a CAS identifier."""

    set_id: str
    packet_objectives: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    effective_diff: str = ""  # the actual wave patch text (bounded)
    semantic_delta: dict[str, Any] = field(default_factory=dict)
    validation_gates: dict[str, bool] = field(default_factory=dict)
    worker_attribution: dict[str, str] = field(default_factory=dict)
    reopened_obligations: list[str] = field(default_factory=list)
    closed_obligations: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    max_diff_bytes: int = 60000

    def prompt_payload(self) -> dict[str, Any]:
        return {
            "setId": self.set_id,
            "packetObjectives": self.packet_objectives,
            "acceptanceCriteria": self.acceptance_criteria,
            "effectiveDiff": self.effective_diff[: self.max_diff_bytes],
            "semanticDelta": self.semantic_delta,
            "validationGates": self.validation_gates,
            "workerAttribution": self.worker_attribution,
            "reopenedObligations": self.reopened_obligations,
            "closedObligations": self.closed_obligations,
            "uncertainties": self.uncertainties,
        }


class AiReviewer:
    """A qualified reviewer agent (billable; gated), independent of the planner,
    critic, workers and integrator. Always advisory — validation stays
    authoritative — but a withheld approval blocks a required review."""

    def __init__(
        self,
        invoke,
        agent_profile_id: str,
        provider_id: str = "",
        model_id: str = "",
        adapter_id: str = "",
    ) -> None:
        self._invoke = invoke
        self.agent_profile_id = agent_profile_id
        self.provider_id = provider_id
        self.model_id = model_id
        self.adapter_id = adapter_id

    async def review(
        self, set_id: str, wave: WavePatch | None, bundle: ReviewContextBundle | None = None
    ) -> WaveReview:
        import json

        from .models import AgentRequest

        payload = (
            bundle.prompt_payload()
            if bundle is not None
            else {"wave": wave.model_dump(mode="json") if wave else {}}
        )
        prompt = (
            "You are an independent USF wave reviewer. Review the ACTUAL diff and "
            "evidence below for RISK only; your review is advisory and never "
            "establishes correctness. Answer each question and return ONLY JSON "
            '{"approved": bool, "findings": [string], "risk_flags": [string]}.\n\n'
            + "\n".join(WAVE_REVIEW_QUESTIONS)
            + "\n\nCONTEXT:\n"
            + json.dumps(payload, sort_keys=True)
        )
        # Explicit routing on the reviewer request (never derived from the id).
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id=f"review:{set_id}",
            instructions=prompt,
            provider_id=self.provider_id,
            requested_model_id=self.model_id,
            adapter_id=self.adapter_id,
        )
        resp = await self._invoke(req)
        findings: list[str] = []
        risk_flags: list[str] = []
        approved = False
        parsed = False
        try:
            data = json.loads(resp.output_text)
            findings = list(data.get("findings", []))
            risk_flags = list(data.get("risk_flags", []))
            approved = bool(data.get("approved", not risk_flags))
            parsed = True
        except (json.JSONDecodeError, TypeError):
            findings = ["reviewer output was not valid JSON"]
        # Fail closed: unparseable review or any risk flag withholds approval.
        return WaveReview(
            set_id=set_id,
            reviewer_profile_id=self.agent_profile_id,
            advisory=True,
            approved=parsed and approved and not risk_flags,
            findings=findings,
            risk_flags=risk_flags,
            reviewed_at=utc_now_iso(),
        )
