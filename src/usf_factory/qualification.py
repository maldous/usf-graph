"""USF qualification engine (build task §8.2).

Loads a versioned qualification corpus (public regression + hidden holdout),
grades answers deterministically, produces per-dimension and per-task-class
scores, and derives admission roles from the trust policy.

Billable qualification (invoking real models) is disabled by default. Scoring is
pure and deterministic so it can be tested with fixture answers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .clock import utc_now_iso
from .config import TrustPolicy
from .enums import ADMISSION_RANK, SCORE_DIMENSIONS, AdmissionRole
from .models import QualificationCase, QualificationRun, QualificationSuite

PASS_THRESHOLD = 0.5


# --------------------------------------------------------------------------- #
# Corpus loading.
# --------------------------------------------------------------------------- #


def _load_case_files(directory: Path, holdout: bool) -> list[QualificationCase]:
    cases: list[QualificationCase] = []
    if not directory.is_dir():
        return cases
    for path in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in data.get("cases", []):
            raw.setdefault("holdout", holdout)
            case = QualificationCase(**raw)
            if case.dimension not in SCORE_DIMENSIONS:
                raise ValueError(f"case {case.case_id} uses unknown dimension '{case.dimension}'")
            cases.append(case)
    return cases


def load_corpus(
    corpus_dir: Path, holdout_dir: Path, *, version: str = "v1", suite_id: str = "usf-qual"
) -> QualificationSuite:
    """Load public + hidden holdout cases into one suite."""
    public = _load_case_files(corpus_dir, holdout=False)
    holdout = _load_case_files(holdout_dir, holdout=True)
    return QualificationSuite(suite_id=suite_id, version=version, cases=public + holdout)


# --------------------------------------------------------------------------- #
# Graders (deterministic).
# --------------------------------------------------------------------------- #


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def grade_case(case: QualificationCase, answer: str) -> float:
    """Grade one answer, returning a score in [0, 1]."""
    grader = case.grader
    exp = case.expected

    if grader == "exact":
        return 1.0 if _norm(answer) == _norm(str(exp.get("value", ""))) else 0.0

    if grader == "contains":
        needles = exp.get("all", [])
        if needles:
            return 1.0 if all(_norm(str(n)) in _norm(answer) for n in needles) else 0.0
        return 1.0 if _norm(str(exp.get("value", ""))) in _norm(answer) else 0.0

    if grader == "not_contains":
        needles = exp.get("any", [exp.get("value", "")])
        return 0.0 if any(_norm(str(n)) in _norm(answer) for n in needles) else 1.0

    if grader == "regex":
        pattern = exp.get("pattern", "")
        return 1.0 if re.search(pattern, answer, re.IGNORECASE | re.DOTALL) else 0.0

    if grader == "iri_exact":
        return 1.0 if str(exp.get("iri", "")) in answer else 0.0

    if grader == "choice":
        want = _norm(str(exp.get("value", "")))
        # Accept exact token match at start or as a standalone word.
        return 1.0 if re.search(rf"\b{re.escape(want)}\b", _norm(answer)) else 0.0

    if grader == "set_equal":
        want_set = {_norm(str(x)) for x in exp.get("values", [])}
        got = {_norm(x) for x in re.split(r"[,\n;]+", answer) if x.strip()}
        return 1.0 if want_set == got else 0.0

    if grader == "json_schema":
        data = _extract_json(answer)
        if data is None:
            return 0.0
        try:
            jsonschema.validate(data, exp.get("schema", {}))
            return 1.0
        except jsonschema.ValidationError:
            return 0.0

    if grader == "uncertainty":
        markers = ("i don't know", "cannot", "unknown", "uncertain", "insufficient", "not enough")
        return 1.0 if any(m in answer.lower() for m in markers) else 0.0

    raise ValueError(f"unknown grader: {grader}")


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"[\{\[].*[\}\]]", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


# --------------------------------------------------------------------------- #
# Scoring & admission (pure).
# --------------------------------------------------------------------------- #


def _weighted_mean(pairs: list[tuple[float, float]]) -> float:
    """pairs of (score, weight)."""
    total_w = sum(w for _, w in pairs)
    if total_w == 0:
        return 0.0
    return sum(s * w for s, w in pairs) / total_w


def score_answers(
    suite: QualificationSuite, answers: dict[str, str]
) -> tuple[dict[str, float], dict[str, float], int, int]:
    """Return (dimension_scores, task_class_scores, cases_passed, cases_total).

    Every case in the suite counts. A MISSING answer scores 0 (a model cannot
    earn a high average by answering only the easy cases). ``total`` is the full
    suite size, not just the answered subset.
    """
    by_dim: dict[str, list[tuple[float, float]]] = {}
    by_tc: dict[str, list[tuple[float, float]]] = {}
    passed = 0
    total = 0
    for case in suite.cases:
        total += 1
        if case.case_id in answers:
            s = grade_case(case, answers[case.case_id])
        else:
            s = 0.0  # unanswered case scores zero (fail closed)
        if s >= PASS_THRESHOLD:
            passed += 1
        by_dim.setdefault(case.dimension, []).append((s, case.weight))
        by_tc.setdefault(case.task_class, []).append((s, case.weight))
    dim_scores = {d: round(_weighted_mean(v), 4) for d, v in by_dim.items()}
    tc_scores = {t: round(_weighted_mean(v), 4) for t, v in by_tc.items()}
    return dim_scores, tc_scores, passed, total


def compute_admission_roles(
    dimension_scores: dict[str, float], trust: TrustPolicy
) -> list[AdmissionRole]:
    """Roles whose every threshold is satisfied. Never grants write roles
    unless earned; defaults to UNQUALIFIED when nothing qualifies."""
    admitted: list[AdmissionRole] = []
    for role, thresh in trust.role_thresholds.items():
        if all(dimension_scores.get(dim, 0.0) >= minv for dim, minv in thresh.min_scores.items()):
            admitted.append(role)
    if not admitted:
        return [AdmissionRole.UNQUALIFIED]
    admitted.sort(key=lambda r: ADMISSION_RANK[r])
    return admitted


def build_run(
    *,
    agent_profile_id: str,
    suite: QualificationSuite,
    answers: dict[str, str],
    trust: TrustPolicy,
    billable: bool = False,
    expiry_days: int = 30,
    run_id: str = "",
    config_digest: str = "",
    requested_model_id: str = "",
    prompt_version: str = "v1",
    tool_profile: str = "default",
    probe_run_id: str = "",
    actual_models: list[str] | None = None,
    holdout_digest: str = "",
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: float = 0.0,
) -> QualificationRun:
    from .ids import ulid

    dim_scores, tc_scores, passed, total = score_answers(suite, answers)
    roles = compute_admission_roles(dim_scores, trust)
    return QualificationRun(
        run_id=run_id or f"qual-{ulid()}",
        agent_profile_id=agent_profile_id,
        suite_id=suite.suite_id,
        suite_version=suite.version,
        suite_digest=suite.suite_digest(),
        holdout_digest=holdout_digest,
        config_digest=config_digest,
        prompt_version=prompt_version,
        tool_profile=tool_profile,
        requested_model_id=requested_model_id,
        actual_models=actual_models or [],
        probe_run_id=probe_run_id,
        dimension_scores=dim_scores,
        task_class_scores=tc_scores,
        cases_passed=passed,
        cases_total=total,
        roles_admitted=roles,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost_usd,
        billable=billable,
        ran_at=utc_now_iso(),
        expires_at="",  # engine/admission stamps concrete expiry
    )


# --------------------------------------------------------------------------- #
# Answer collection (I/O; billable — gated by caller).
# --------------------------------------------------------------------------- #

Responder = Callable[[QualificationCase], Awaitable[str]]


def fixture_responder(mapping: dict[str, str]) -> Responder:
    """A deterministic responder backed by a case_id -> answer map."""

    async def _respond(case: QualificationCase) -> str:
        return mapping.get(case.case_id, "")

    return _respond


async def collect_answers(suite: QualificationSuite, responder: Responder) -> dict[str, str]:
    answers: dict[str, str] = {}
    for case in suite.cases:
        answers[case.case_id] = await responder(case)
    return answers
