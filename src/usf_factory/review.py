"""Independent wave review (DESIGN Phase 12).

Review is advisory and risk-discovering — it is NEVER proof. Deterministic
validation remains authoritative. Reviewers should come from a different provider
than the integrator to reduce correlated failure.
"""

from __future__ import annotations

from typing import Protocol

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
    async def review(self, set_id: str, wave: WavePatch | None) -> WaveReview: ...


class NoopReviewer:
    """Advisory reviewer that records no findings (e.g. no wave patch to review)."""

    async def review(self, set_id: str, wave: WavePatch | None) -> WaveReview:
        findings = (
            [] if wave is None else ["no automated reviewer configured; manual review advised"]
        )
        return WaveReview(
            set_id=set_id,
            reviewer_profile_id="noop-reviewer",
            advisory=True,
            findings=findings,
            risk_flags=[],
            reviewed_at=utc_now_iso(),
        )


class AiReviewer:
    """Wraps a qualified reviewer agent (billable; gated). Always advisory."""

    def __init__(self, invoke, agent_profile_id: str) -> None:
        self._invoke = invoke
        self.agent_profile_id = agent_profile_id

    async def review(self, set_id: str, wave: WavePatch | None) -> WaveReview:
        import json

        from .models import AgentRequest

        prompt = (
            "You are an independent USF wave reviewer. Review the wave for RISK only; "
            "your review is advisory and never establishes correctness. Answer each "
            'question and return ONLY JSON {"findings": [], "risk_flags": []}.\n\n'
            + "\n".join(WAVE_REVIEW_QUESTIONS)
            + f"\n\nWAVE: {json.dumps(wave.model_dump(mode='json') if wave else {}, sort_keys=True)}"
        )
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id=f"review:{set_id}",
            instructions=prompt,
        )
        resp = await self._invoke(req)
        findings: list[str] = []
        risk_flags: list[str] = []
        parsed = False
        try:
            data = json.loads(resp.output_text)
            findings = list(data.get("findings", []))
            risk_flags = list(data.get("risk_flags", []))
            parsed = True
        except (json.JSONDecodeError, TypeError):
            findings = ["reviewer output was not valid JSON"]
        # Fail closed: unparseable review or any risk flag withholds approval.
        return WaveReview(
            set_id=set_id,
            reviewer_profile_id=self.agent_profile_id,
            advisory=True,
            approved=parsed and not risk_flags,
            findings=findings,
            risk_flags=risk_flags,
            reviewed_at=utc_now_iso(),
        )
