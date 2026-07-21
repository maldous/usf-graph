"""Deterministic validation runners (build task §15 / review §15).

Maps validation-profile names to executable runners operating on the integration
clone. A runner returns ``(True|False, detail)`` for a real verdict or
``(None, detail)`` for an explicit not-applicable. ``run_validation`` treats a
REQUIRED gate with **no** runner as a failure — never a green skip.

Gates that require the live USF validation toolchain (SHACL, integrity SPARQL,
competency queries, negative fixtures, derived regeneration, source/live drift,
proof/readiness) are **not wired in this environment** and their runners FAIL
closed, so a USF wave cannot go green here until an operator wires them.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from .sandbox import scan_secrets

GateRunner = Callable[[], "tuple[bool | None, str]"]

# Requires the live USF validation toolchain; deliberately fail-closed here.
_USF_GATES = (
    "shacl",
    "integrity-sparql",
    "negative-fixtures",
    "competency-queries",
    "manifest-check",
    "derived-regen",
    "source-live-drift",
    "proof-readiness",
)


def _changed_files(clone: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(clone), "diff", "--cached", "--name-only", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout
    return [p for p in out.split() if p.strip()]


def build_runners(clone: Path) -> dict[str, GateRunner]:
    changed = _changed_files(clone)

    def syntax_parse() -> tuple[bool | None, str]:
        rdf = [p for p in changed if p.endswith((".ttl", ".trig", ".rq", ".sparql", ".n3"))]
        if not rdf:
            return None, "no RDF/SPARQL files changed"
        for rel in rdf:
            text = (clone / rel).read_text(encoding="utf-8", errors="replace")
            if text.count("<") != text.count(">"):
                return False, f"unbalanced IRI brackets in {rel}"
            if rel.endswith((".ttl", ".trig")) and text.strip() and "." not in text:
                return False, f"no statements terminated in {rel}"
        return True, f"{len(rdf)} RDF/SPARQL file(s) parse-checked"

    def _ruff(cmd: list[str], label: str) -> tuple[bool | None, str]:
        pyfiles = [p for p in changed if p.endswith(".py")]
        if not pyfiles:
            return None, "no python files changed"
        r = subprocess.run(
            ["ruff", *cmd, *pyfiles], cwd=str(clone), capture_output=True, text=True, timeout=120
        )
        return (r.returncode == 0, f"{label}: rc={r.returncode}")

    def fmt() -> tuple[bool | None, str]:
        return _ruff(["format", "--check"], "format")

    def lint() -> tuple[bool | None, str]:
        return _ruff(["check"], "lint")

    def type_check() -> tuple[bool | None, str]:
        pyfiles = [p for p in changed if p.endswith(".py")]
        if not pyfiles:
            return None, "no python files changed"
        r = subprocess.run(
            ["mypy", "--ignore-missing-imports", "--no-error-summary", *pyfiles],
            cwd=str(clone),
            capture_output=True,
            text=True,
            timeout=180,
        )
        return (r.returncode == 0, f"mypy rc={r.returncode}")

    def unit_tests() -> tuple[bool | None, str]:
        if not (clone / "tests").is_dir():
            return None, "no tests/ directory"
        r = subprocess.run(
            ["python", "-m", "pytest", "-q"],
            cwd=str(clone),
            capture_output=True,
            text=True,
            timeout=600,
        )
        return (r.returncode == 0, f"pytest rc={r.returncode}")

    def secret_scan() -> tuple[bool | None, str]:
        for rel in changed:
            try:
                if scan_secrets((clone / rel).read_text(encoding="utf-8", errors="replace")):
                    return False, f"secret-shaped content in {rel}"
            except OSError:
                continue
        return True, "no secret-shaped content in changed files"

    def repo_clean() -> tuple[bool | None, str]:
        for rel in changed:
            try:
                text = (clone / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "<<<<<<< " in text or ">>>>>>> " in text or rel.endswith((".orig", ".rej")):
                return False, f"merge markers/artifacts in {rel}"
        return True, "no merge markers"

    runners: dict[str, GateRunner] = {
        "syntax-parse": syntax_parse,
        "format": fmt,
        "lint": lint,
        "type": type_check,
        "unit-tests": unit_tests,
        "integration-tests": unit_tests,
        "secret-scan": secret_scan,
        "repository-cleanliness": repo_clean,
    }

    def _env_blocked(g: str) -> GateRunner:
        def _runner() -> tuple[bool | None, str]:
            return (False, f"{g}: USF validation toolchain not wired here (ENVIRONMENT_BLOCKED)")

        return _runner

    for gate in _USF_GATES:
        runners[gate] = _env_blocked(gate)
    return runners
