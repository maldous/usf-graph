"""Actual semantic-delta extraction from an effective patch (Phase 9).

The semantic delta is derived from the PATCH BYTES, never from worker claims. It
parses added/removed lines per changed file, classifies the file, and extracts
the RDF subjects, shape targets, rules, generated-output impacts, runtime symbols
and tests/fixtures affected. This feeds conflict detection, scope validation, and
the review context bundle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .materialisation import _DECL_RE, _TERM, _classify_path, _expand, _strip_comments

_HUNK_FILE = re.compile(r"^\+\+\+ [ab]/(.+)$")
_PY_DEF = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)")


@dataclass
class SemanticDelta:
    iris_added: list[str] = field(default_factory=list)
    iris_removed: list[str] = field(default_factory=list)
    iris_modified: list[str] = field(default_factory=list)
    shape_targets_changed: list[str] = field(default_factory=list)
    rules_changed: list[str] = field(default_factory=list)
    generated_impacts: list[str] = field(default_factory=list)
    runtime_symbols_changed: list[str] = field(default_factory=list)
    tests_changed: list[str] = field(default_factory=list)
    changed_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "iris_added": self.iris_added,
            "iris_removed": self.iris_removed,
            "iris_modified": self.iris_modified,
            "shape_targets_changed": self.shape_targets_changed,
            "rules_changed": self.rules_changed,
            "generated_impacts": self.generated_impacts,
            "runtime_symbols_changed": self.runtime_symbols_changed,
            "tests_changed": self.tests_changed,
            "changed_paths": self.changed_paths,
        }

    @property
    def semantic_subjects(self) -> list[str]:
        return sorted(set(self.iris_added) | set(self.iris_removed) | set(self.iris_modified))


def _split_by_file(patch: str) -> dict[str, tuple[list[str], list[str]]]:
    """Return {path: (added_lines, removed_lines)} from a unified diff."""
    per: dict[str, tuple[list[str], list[str]]] = {}
    cur: str | None = None
    for line in patch.splitlines():
        m = _HUNK_FILE.match(line)
        if m:
            cur = m.group(1)
            per.setdefault(cur, ([], []))
            continue
        if cur is None or line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            per[cur][0].append(line[1:])
        elif line.startswith("-"):
            per[cur][1].append(line[1:])
    return per


def _all_prefixes(patch: str) -> dict[str, str]:
    """Collect @prefix / PREFIX declarations from the ENTIRE patch (context lines
    carry prefixes even when the changed line does not), so a bare-prefix subject
    on an added/removed line still expands."""
    from .materialisation import _PREFIX_RE, _SPARQL_PREFIX_RE

    stripped = "\n".join((line[1:] if line[:1] in "+- " else line) for line in patch.splitlines())
    stripped = _strip_comments(stripped)
    prefixes: dict[str, str] = {}
    for m in _PREFIX_RE.finditer(stripped):
        prefixes[m.group(1) or ""] = m.group(2)
    for m in _SPARQL_PREFIX_RE.finditer(stripped):
        prefixes[m.group(1) or ""] = m.group(2)
    return prefixes


def _declared_iris(lines: list[str], prefixes: dict[str, str]) -> set[str]:
    text = _strip_comments("\n".join(lines))
    out: set[str] = set()
    for m in _DECL_RE.finditer(text):
        iri = _expand(m.group(1), prefixes)
        if iri:
            out.add(iri)
    return out


def _referenced_iris(lines: list[str], prefixes: dict[str, str]) -> set[str]:
    text = _strip_comments("\n".join(lines))
    out: set[str] = set()
    for tok in re.findall(_TERM, text):
        iri = _expand(tok, prefixes)
        if iri:
            out.add(iri)
    return out


def extract_semantic_delta(patch: str) -> SemanticDelta:
    """Derive the semantic delta from a unified diff (patch bytes only)."""
    delta = SemanticDelta()
    per = _split_by_file(patch)
    delta.changed_paths = sorted(per)
    prefixes = _all_prefixes(patch)
    for path, (added, removed) in sorted(per.items()):
        kind, _profiles = _classify_path(path)
        if kind in ("ontology", "shape", "rule", "generated", "manifest", "test") or path.endswith(
            (".ttl", ".trig", ".rq", ".sparql", ".n3", ".nt")
        ):
            add_decl = _declared_iris(added, prefixes)
            rem_decl = _declared_iris(removed, prefixes)
            delta.iris_added.extend(sorted(add_decl - rem_decl))
            delta.iris_removed.extend(sorted(rem_decl - add_decl))
            delta.iris_modified.extend(sorted(add_decl & rem_decl))
            if kind == "shape":
                # sh:targetClass / sh:targetNode references that changed.
                changed_refs = _referenced_iris(added, prefixes) ^ _referenced_iris(
                    removed, prefixes
                )
                delta.shape_targets_changed.extend(sorted(changed_refs))
            elif kind == "rule":
                delta.rules_changed.append(path)
            elif kind == "generated":
                delta.generated_impacts.append(path)
        elif kind == "test":
            delta.tests_changed.append(path)
        if path.endswith(".py"):
            for line in added + removed:
                m = _PY_DEF.match(line)
                if m:
                    delta.runtime_symbols_changed.append(f"{path}:{m.group(1)}")
    # Dedup.
    for f in (
        "iris_added",
        "iris_removed",
        "iris_modified",
        "shape_targets_changed",
        "rules_changed",
        "generated_impacts",
        "runtime_symbols_changed",
        "tests_changed",
    ):
        setattr(delta, f, sorted(set(getattr(delta, f))))
    return delta
