"""Mechanical capability probes (build task §8.1).

Ten versioned probes with generic, non-sensitive prompts. Probes NEVER include
/usf source during provider testing. Grading is deterministic given the raw
model output, so a stored probe response replays to the same verdict.

Model invocation itself is billable and gated elsewhere; this module defines the
specs and the deterministic graders.
"""

from __future__ import annotations

import json
import re
from typing import Any

import jsonschema

from .enums import ProbeKind
from .models import ProbeResult, ProbeSpec

PROBE_VERSION = "v1"

_UNCERTAINTY_MARKERS = (
    "i don't know",
    "i do not know",
    "cannot determine",
    "insufficient information",
    "unknown",
    "unsure",
    "not enough information",
    "uncertain",
    # Common genuine-uncertainty phrasings strong models use.
    "no way to know",
    "cannot know",
    "can't know",
    "cannot possibly know",
    "have no way",
    "don't have access",
    "do not have access",
    "no access to",
    "unable to determine",
    "unable to know",
    "impossible to know",
    "cannot be determined",
    "not possible to know",
    "i don't have",
    "i cannot",
    "i can't",
)


def default_probe_specs() -> list[ProbeSpec]:
    """The canonical ten mechanical probes. Prompts are generic and safe."""
    return [
        ProbeSpec(
            kind=ProbeKind.TEXT_RESPONSE,
            prompt="Reply with a single short sentence describing what a checksum is.",
        ),
        ProbeSpec(
            kind=ProbeKind.STRICT_JSON,
            prompt=(
                'Return ONLY JSON matching {"name": string, "count": integer}. '
                "Use name='probe' and count=3. No prose."
            ),
            expected={
                "schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "count": {"type": "integer"}},
                    "required": ["name", "count"],
                    "additionalProperties": False,
                }
            },
        ),
        ProbeSpec(
            kind=ProbeKind.FORCED_TOOL_CALL,
            prompt="Call the tool `lookup` with argument key='alpha'. Do not answer in prose.",
            permitted_tools=["lookup"],
            expected={"tool": "lookup", "args": {"key": "alpha"}},
        ),
        ProbeSpec(
            kind=ProbeKind.TOOL_RESULT_FOLLOWUP,
            prompt=(
                'You called `lookup` and received the result {"value": 42}. '
                'Now return ONLY JSON {"value": integer} echoing the value.'
            ),
            expected={"value": 42},
        ),
        ProbeSpec(
            kind=ProbeKind.PROHIBITED_TOOL_COMPLIANCE,
            prompt=(
                "Answer the question 'what is 2+2?' in one word. "
                "You are forbidden from calling any tool."
            ),
            prohibited_tools=["shell", "write_file", "network"],
            expected={"answer": "4"},
        ),
        ProbeSpec(
            kind=ProbeKind.IRI_PRESERVATION,
            prompt=(
                "Echo this IRI back EXACTLY once, unchanged, on its own line: "
                "https://example.org/usf#Capability_A1b2C3"
            ),
            expected={"iri": "https://example.org/usf#Capability_A1b2C3"},
        ),
        ProbeSpec(
            kind=ProbeKind.DIGEST_PRESERVATION,
            prompt=(
                "Echo this digest back EXACTLY, unchanged: "
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            expected={
                "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
        ),
        ProbeSpec(
            kind=ProbeKind.EXPLICIT_UNCERTAINTY,
            prompt=(
                "What is the internal employee ID of the person who wrote line 5 of a file "
                "you have never seen? If you cannot know, say so explicitly rather than guessing."
            ),
            expected={"expect_uncertainty": True},
        ),
        ProbeSpec(
            kind=ProbeKind.STOP_CONDITION,
            prompt=(
                "List the first three positive integers, one per line, then STOP. "
                "End your output with the exact token <<END>> and nothing after it."
            ),
            expected={"stop_token": "<<END>>"},
        ),
        ProbeSpec(
            kind=ProbeKind.PATCH_FORMAT,
            prompt=(
                "Produce a unified diff (git format) that adds a line 'hello' to a file "
                "named greeting.txt. Output only the diff."
            ),
            expected={"unified_diff": True},
        ),
    ]


# --------------------------------------------------------------------------- #
# Deterministic graders.
# --------------------------------------------------------------------------- #


def _extract_json(text: str) -> Any:
    text = text.strip()
    # Strip markdown fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find the first {...} block.
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


def grade_probe(
    spec: ProbeSpec,
    raw_output: str,
    structured: dict[str, Any] | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
    actual_model_id: str | None = None,
) -> ProbeResult:
    """Grade a probe deterministically."""
    structured = structured or {}
    tool_calls = tool_calls or []
    passed = False
    detail = ""

    k = spec.kind
    if k is ProbeKind.TEXT_RESPONSE:
        passed = bool(raw_output.strip())
        detail = "non-empty text" if passed else "empty response"

    elif k is ProbeKind.STRICT_JSON:
        data = structured or _extract_json(raw_output)
        schema = spec.expected.get("schema", {})
        if data is not None:
            try:
                jsonschema.validate(data, schema)
                passed = True
                detail = "valid JSON per schema"
            except jsonschema.ValidationError as exc:
                detail = f"schema violation: {exc.message}"
        else:
            detail = "not valid JSON"

    elif k is ProbeKind.FORCED_TOOL_CALL:
        want = spec.expected
        for call in tool_calls:
            if call.get("name") == want.get("tool") and call.get("arguments") == want.get("args"):
                passed = True
                break
        detail = "expected tool call present" if passed else "expected tool call absent"

    elif k is ProbeKind.TOOL_RESULT_FOLLOWUP:
        data = structured or _extract_json(raw_output)
        passed = isinstance(data, dict) and data.get("value") == spec.expected.get("value")
        detail = "echoed tool result" if passed else "did not echo tool result"

    elif k is ProbeKind.PROHIBITED_TOOL_COMPLIANCE:
        called_prohibited = any(c.get("name") in spec.prohibited_tools for c in tool_calls)
        answered = "4" in raw_output
        passed = (not called_prohibited) and answered
        detail = (
            "complied (no prohibited tool)" if passed else "used prohibited tool or wrong answer"
        )

    elif k is ProbeKind.IRI_PRESERVATION:
        iri = spec.expected.get("iri", "")
        passed = iri in raw_output
        detail = "IRI preserved exactly" if passed else "IRI altered/missing"

    elif k is ProbeKind.DIGEST_PRESERVATION:
        digest = spec.expected.get("digest", "")
        passed = digest in raw_output
        detail = "digest preserved exactly" if passed else "digest altered/missing"

    elif k is ProbeKind.EXPLICIT_UNCERTAINTY:
        low = raw_output.lower()
        passed = any(m in low for m in _UNCERTAINTY_MARKERS)
        detail = (
            "expressed uncertainty" if passed else "fabricated instead of admitting uncertainty"
        )

    elif k is ProbeKind.STOP_CONDITION:
        token = spec.expected.get("stop_token", "")
        stripped = raw_output.rstrip()
        passed = stripped.endswith(token)
        detail = "stopped at stop token" if passed else "did not honor stop condition"

    elif k is ProbeKind.PATCH_FORMAT:
        passed = _looks_like_unified_diff(raw_output)
        detail = "valid unified diff" if passed else "not a unified diff"

    return ProbeResult(
        kind=spec.kind,
        version=spec.version,
        passed=passed,
        score=1.0 if passed else 0.0,
        detail=detail,
        actual_model_id=actual_model_id,
    )


def _looks_like_unified_diff(text: str) -> bool:
    has_hunk = "@@" in text
    has_headers = ("--- " in text and "+++ " in text) or text.lstrip().startswith("diff --git")
    has_add = any(line.startswith("+") for line in text.splitlines())
    return has_hunk and has_headers and has_add
