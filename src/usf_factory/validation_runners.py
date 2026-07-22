"""Deterministic validation runners (build task §15 / review §15).

Maps validation-profile names to executable runners operating on the integration
clone. A runner returns ``(True|False, detail)`` for a real verdict or
``(None, detail)`` for an explicit not-applicable. ``run_validation`` treats a
REQUIRED gate with **no** runner as a failure — never a green skip.

RDF/TriG/SPARQL parsing, SHACL, and integrity-SPARQL execution are REAL
(``rdflib`` + ``pyshacl``), run in the integration clone. Gates that require the
live USF Node/authority toolchain (competency queries, negative fixtures,
derived regeneration, source/live drift, proof/readiness) are **not wired here**
and their runners FAIL closed, so a full USF wave cannot go green until an
operator wires them.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .sandbox import scan_secrets

GateRunner = Callable[[], "tuple[bool | None, str]"]


def _python_tool(name: str) -> str:
    """Resolve a Python tool from the executing interpreter's environment.

    Validation frequently runs in a clean integration clone where the parent
    process PATH is intentionally minimal.  The interpreter location is the
    stable toolchain binding; falling back to PATH only supports system installs.
    """
    sibling = Path(sys.executable).with_name(name)
    return str(sibling) if sibling.is_file() else name


# These gates need the LIVE USF Node/authority toolchain (drift, regeneration,
# proof, competency/negative fixtures against admitted evidence) and stay
# fail-closed here. syntax-parse / shacl / integrity-sparql are now REAL
# (rdflib + pyshacl) and are NOT in this set.
_USF_GATES = (
    "negative-fixtures",
    "competency-queries",
    "manifest-check",
    "derived-regen",
    "source-live-drift",
    "proof-readiness",
)


def _changed_files(clone: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(clone), "diff", "--cached", "--name-only", "HEAD"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git changed-file discovery failed: {result.stderr.strip()[:160]}")
    return [p for p in result.stdout.splitlines() if p.strip()]


def _tracked_files(clone: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(clone), "ls-files"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git tracked-file discovery failed: {result.stderr.strip()[:160]}")
    return [p for p in result.stdout.splitlines() if p.strip()]


def _rdf_format(rel: str) -> str | None:
    low = rel.lower()
    if low.endswith((".ttl", ".turtle")):
        return "turtle"
    if low.endswith(".trig"):
        return "trig"
    if low.endswith(".nt"):
        return "nt"
    if low.endswith(".n3"):
        return "n3"
    return None


def build_runners(clone: Path) -> dict[str, GateRunner]:
    discovery_error = ""
    try:
        changed = _changed_files(clone)
        tracked = _tracked_files(clone)
    except RuntimeError as exc:
        changed = []
        tracked = []
        discovery_error = str(exc)

    def syntax_parse() -> tuple[bool | None, str]:
        """Real RDF/TriG + SPARQL parse via rdflib (replaces bracket counting)."""
        if discovery_error:
            return False, discovery_error
        rdf = [p for p in changed if _rdf_format(p) is not None]
        sparql = [p for p in changed if p.endswith((".rq", ".sparql"))]
        if not rdf and not sparql:
            return None, "no RDF/SPARQL files changed"
        import rdflib
        from rdflib.plugins.sparql import prepareQuery

        for rel in rdf:
            fmt = _rdf_format(rel)
            try:
                rdflib.Graph().parse(
                    data=(clone / rel).read_text(encoding="utf-8", errors="replace"), format=fmt
                )
            except Exception as exc:
                return False, f"RDF parse failed for {rel}: {type(exc).__name__}: {str(exc)[:120]}"
        for rel in sparql:
            try:
                prepareQuery((clone / rel).read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                return (
                    False,
                    f"SPARQL parse failed for {rel}: {type(exc).__name__}: {str(exc)[:120]}",
                )
        return True, f"parsed {len(rdf)} RDF + {len(sparql)} SPARQL file(s) via rdflib"

    def shacl() -> tuple[bool | None, str]:
        """Validate the complete tracked data against complete tracked shapes."""
        if discovery_error:
            return False, discovery_error
        changed_rdf = [p for p in changed if _rdf_format(p) is not None]
        if not changed_rdf:
            return None, "no RDF or SHACL files changed"
        shapes = [p for p in tracked if "/shapes/" in p.lower() or p.lower().endswith(".shacl.ttl")]
        data = [
            p
            for p in tracked
            if _rdf_format(p) is not None
            and "/shapes/" not in p.lower()
            and not p.lower().endswith(".shacl.ttl")
        ]
        if not shapes:
            return False, "SHACL gate requested but no tracked shape graph exists"
        if not data:
            return False, "SHACL gate requested but no tracked data graph exists"
        import pyshacl
        import rdflib

        shapes_g = rdflib.Graph()
        try:
            for rel in shapes:
                shapes_g.parse(
                    data=(clone / rel).read_text(encoding="utf-8", errors="replace"),
                    format="turtle",
                )
            data_g = rdflib.Dataset()
            for rel in data:
                data_g.parse(
                    data=(clone / rel).read_text(encoding="utf-8", errors="replace"),
                    format=_rdf_format(rel),
                )
        except Exception as exc:
            return (
                False,
                f"canonical SHACL input parse failed: {type(exc).__name__}: {str(exc)[:120]}",
            )
        try:
            conforms, _rg, text = pyshacl.validate(data_g, shacl_graph=shapes_g, inference="none")
        except Exception as exc:
            return False, f"pyshacl error: {type(exc).__name__}: {str(exc)[:120]}"
        return conforms, ("SHACL conforms" if conforms else f"SHACL violations: {text[:150]}")

    def _ruff(cmd: list[str], label: str) -> tuple[bool | None, str]:
        if discovery_error:
            return False, discovery_error
        pyfiles = [p for p in changed if p.endswith(".py")]
        if not pyfiles:
            return None, "no python files changed"
        r = subprocess.run(
            [_python_tool("ruff"), *cmd, *pyfiles],
            cwd=str(clone),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return (r.returncode == 0, f"{label}: rc={r.returncode}")

    def fmt() -> tuple[bool | None, str]:
        return _ruff(["format", "--check"], "format")

    def lint() -> tuple[bool | None, str]:
        return _ruff(["check"], "lint")

    def type_check() -> tuple[bool | None, str]:
        if discovery_error:
            return False, discovery_error
        pyfiles = [p for p in changed if p.endswith(".py")]
        if not pyfiles:
            return None, "no python files changed"
        r = subprocess.run(
            [_python_tool("mypy"), "--ignore-missing-imports", "--no-error-summary", *pyfiles],
            cwd=str(clone),
            capture_output=True,
            text=True,
            timeout=180,
        )
        return (r.returncode == 0, f"mypy rc={r.returncode}")

    def unit_tests() -> tuple[bool | None, str]:
        if discovery_error:
            return False, discovery_error
        if not (clone / "tests").is_dir():
            return None, "no tests/ directory"
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=str(clone),
            capture_output=True,
            text=True,
            timeout=600,
        )
        return (r.returncode == 0, f"pytest rc={r.returncode}")

    def secret_scan() -> tuple[bool | None, str]:
        if discovery_error:
            return False, discovery_error
        for rel in changed:
            try:
                if scan_secrets((clone / rel).read_text(encoding="utf-8", errors="replace")):
                    return False, f"secret-shaped content in {rel}"
            except OSError:
                continue
        return True, "no secret-shaped content in changed files"

    def repo_clean() -> tuple[bool | None, str]:
        if discovery_error:
            return False, discovery_error
        for rel in changed:
            try:
                text = (clone / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "<<<<<<< " in text or ">>>>>>> " in text or rel.endswith((".orig", ".rej")):
                return False, f"merge markers/artifacts in {rel}"
        return True, "no merge markers"

    def integrity_sparql() -> tuple[bool | None, str]:
        """Real: parse each changed .rq/.sparql and EXECUTE it against a graph
        built from the changed RDF (a genuine run — not against live Stardog).
        A query that fails to parse or execute fails the gate."""
        if discovery_error:
            return False, discovery_error
        queries = [p for p in changed if p.endswith((".rq", ".sparql"))]
        if not queries:
            return None, "no SPARQL queries changed"
        import rdflib

        g = rdflib.Dataset()
        for rel in tracked:
            fmt = _rdf_format(rel)
            if fmt is None:
                continue
            try:
                g.parse(
                    data=(clone / rel).read_text(encoding="utf-8", errors="replace"), format=fmt
                )
            except Exception as exc:
                return (
                    False,
                    f"canonical integrity input parse failed for {rel}: {type(exc).__name__}",
                )
        for rel in queries:
            try:
                result = g.query((clone / rel).read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                return False, f"SPARQL execution failed for {rel}: {type(exc).__name__}"
            if result.type == "ASK":
                violations = bool(result.askAnswer)
            elif result.type in {"CONSTRUCT", "DESCRIBE"}:
                violations = bool(result.graph and len(result.graph))
            else:
                violations = next(iter(result), None) is not None
            if violations:
                return False, f"integrity violations returned by {rel}"
        return True, f"executed {len(queries)} zero-result integrity query/queries via rdflib"

    runners: dict[str, GateRunner] = {
        "syntax-parse": syntax_parse,
        "shacl": shacl,
        "integrity-sparql": integrity_sparql,
        "format": fmt,
        "lint": lint,
        "type": type_check,
        "unit-tests": unit_tests,
        "integration-tests": unit_tests,
        # Bounded focused tests run the same real pytest gate (N/A when no test
        # files changed); a real runner, never a stub.
        "focused-tests": unit_tests,
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
