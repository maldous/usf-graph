"""Semantic subject -> repository materialisation index (build task §6 / review P0-9).

Maps a semantic subject IRI to the exact repository surface that materialises it:
the authored source file that OWNS it, related sources, SHACL shapes, SPARQL
rules, tests, and generated outputs. The deterministic packet compiler derives
read/write scope and validation profiles from this index — the planner never
provides authoritative filesystem scope.

The index describes WHERE a subject materialises; it never asserts that repository
content is admitted semantic truth (that is the MCP authority boundary's job).

Parsing is conservative (prefix-aware Turtle/TriG subject extraction + directory/
naming heuristics) and every mapping carries method/confidence/provenance. A
mutating packet requires a ``verified`` owner for every semantic subject and a
mapping for every generated output; otherwise it fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import content_digest

INDEX_VERSION = "mat-index-v1"

_RDF_SUFFIXES = (".ttl", ".trig", ".turtle", ".nt", ".n3")
_PREFIX_RE = re.compile(r"^\s*@?prefix\s+([A-Za-z][\w.\-]*):\s*<([^>]*)>\s*\.?", re.IGNORECASE)
_SPARQL_PREFIX_RE = re.compile(r"^\s*PREFIX\s+([A-Za-z][\w.\-]*):\s*<([^>]*)>", re.IGNORECASE)
# A subject DECLARATION at statement start: <iri> a  OR pfx:local a  (rdf:type).
_DECL_RE = re.compile(r"^\s*(<[^>]+>|[A-Za-z][\w.\-]*:[\w.\-]+)\s+(?:a|rdf:type)\b")
_TOKEN_RE = re.compile(r"<[^>]+>|[A-Za-z][\w.\-]*:[\w.\-]+")


@dataclass
class MaterialisationEntry:
    subject: str
    owner_path: str | None = None
    related_paths: list[str] = field(default_factory=list)
    shapes: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    generated_outputs: list[str] = field(default_factory=list)
    validation_profiles: list[str] = field(default_factory=list)
    method: str = "inferred"  # "parsed-declaration" | "inferred" | "ambiguous"
    confidence: float = 0.0
    verified: bool = False


@dataclass
class ScopeResult:
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    generated_outputs: list[str] = field(default_factory=list)
    validation_profiles: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)  # subjects with no verified owner
    ambiguous: list[str] = field(default_factory=list)  # subjects with >1 owner

    @property
    def ok(self) -> bool:
        return not self.unresolved and not self.ambiguous


def _expand(term: str, prefixes: dict[str, str]) -> str | None:
    if term.startswith("<") and term.endswith(">"):
        return term[1:-1]
    if ":" in term:
        pfx, local = term.split(":", 1)
        base = prefixes.get(pfx)
        if base is not None:
            return base + local
    return None


def _classify_path(rel: str) -> tuple[str, list[str]]:
    """Return (kind, validation_profiles) for a file by path/naming heuristics."""
    low = rel.lower()
    if any(seg in low for seg in ("/generated/", "/derived/", "generated-", "derived-")):
        return "generated", []
    if low.endswith((".rq", ".sparql")) or "/queries/" in low or "/rules/" in low:
        return "rule", ["syntax-parse", "integrity-sparql"]
    if "/shapes/" in low or "shacl" in low or low.endswith(".shacl.ttl"):
        return "shape", ["syntax-parse", "shacl"]
    if (
        "/tests/" in low
        or "/test/" in low
        or "/fixtures/" in low
        or "test_" in low.rsplit("/", 1)[-1]
    ):
        return "test", ["negative-fixtures"]
    if low.endswith(_RDF_SUFFIXES):
        return "ontology", ["syntax-parse", "shacl"]
    return "other", []


class MaterialisationIndex:
    def __init__(self, root: Path, *, index_version: str = INDEX_VERSION) -> None:
        self.root = Path(root)
        self.index_version = index_version
        self.entries: dict[str, MaterialisationEntry] = {}
        self.source_digest: str = ""
        self._owner_counts: dict[str, set[str]] = {}

    # ---- build ---------------------------------------------------------- #

    def build(
        self, include: tuple[str, ...] = (*_RDF_SUFFIXES, ".rq", ".sparql")
    ) -> MaterialisationIndex:
        files = sorted(
            p
            for p in self.root.rglob("*")
            if p.is_file()
            and ".git/" not in str(p.relative_to(self.root)) + "/"
            and p.suffix.lower() in include
        )
        file_digests: dict[str, str] = {}
        for path in files:
            rel = str(path.relative_to(self.root))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            file_digests[rel] = content_digest({"path": rel, "text": text})
            self._index_file(rel, text)
        # Resolve ambiguity + confidence.
        for subj, entry in self.entries.items():
            owners = self._owner_counts.get(subj, set())
            if len(owners) == 1:
                entry.owner_path = next(iter(owners))
                entry.method = "parsed-declaration"
                entry.confidence = 0.95
                entry.verified = True
            elif len(owners) > 1:
                entry.method = "ambiguous"
                entry.confidence = 0.3
                entry.verified = False
            else:
                entry.method = "inferred"
                entry.confidence = 0.4
                entry.verified = False
            entry.related_paths = sorted(set(entry.related_paths))
            entry.validation_profiles = sorted(set(entry.validation_profiles))
        self.source_digest = content_digest(
            {"version": self.index_version, "files": dict(sorted(file_digests.items()))}
        )
        return self

    def _index_file(self, rel: str, text: str) -> None:
        kind, profiles = _classify_path(rel)
        prefixes: dict[str, str] = {}
        # Collect prefixes first (both Turtle and SPARQL forms).
        for line in text.splitlines():
            m = _PREFIX_RE.match(line) or _SPARQL_PREFIX_RE.match(line)
            if m:
                prefixes[m.group(1)] = m.group(2)
        # Declarations (owner) + mentions (related).
        for line in text.splitlines():
            decl = _DECL_RE.match(line)
            if decl:
                iri = _expand(decl.group(1), prefixes)
                if iri:
                    e = self.entries.setdefault(iri, MaterialisationEntry(subject=iri))
                    self._owner_counts.setdefault(iri, set()).add(rel)
                    self._attach(e, rel, kind, profiles)
            for tok in _TOKEN_RE.findall(line):
                iri = _expand(tok, prefixes)
                if iri and iri in self.entries:
                    e = self.entries[iri]
                    if rel not in e.related_paths:
                        e.related_paths.append(rel)
                    self._attach(e, rel, kind, profiles, related_only=True)

    def _attach(
        self,
        e: MaterialisationEntry,
        rel: str,
        kind: str,
        profiles: list[str],
        related_only: bool = False,
    ) -> None:
        if kind == "shape" and rel not in e.shapes:
            e.shapes.append(rel)
        elif kind == "rule" and rel not in e.rules:
            e.rules.append(rel)
        elif kind == "test" and rel not in e.tests:
            e.tests.append(rel)
        elif kind == "generated" and rel not in e.generated_outputs:
            e.generated_outputs.append(rel)
        if rel not in e.related_paths:
            e.related_paths.append(rel)
        for p in profiles:
            if p not in e.validation_profiles:
                e.validation_profiles.append(p)

    # ---- query ---------------------------------------------------------- #

    def resolve(self, iri: str) -> MaterialisationEntry | None:
        return self.entries.get(iri)

    def affected_by(self, path: str) -> list[str]:
        return sorted(
            s for s, e in self.entries.items() if path == e.owner_path or path in e.related_paths
        )

    def derive_scope(self, subjects: list[str]) -> ScopeResult:
        """Fail-closed scope derivation for a set of semantic subjects."""
        result = ScopeResult()
        read: set[str] = set()
        write: set[str] = set()
        gen: set[str] = set()
        profiles: set[str] = set()
        for subj in subjects:
            e = self.entries.get(subj)
            if e is None:
                result.unresolved.append(subj)
                continue
            if e.method == "ambiguous":
                result.ambiguous.append(subj)
                continue
            if not (e.verified and e.owner_path):
                result.unresolved.append(subj)
                continue
            write.add(e.owner_path)
            read.update([e.owner_path, *e.related_paths])
            gen.update(e.generated_outputs)
            profiles.update(e.validation_profiles)
        result.read_paths = sorted(read)
        result.write_paths = sorted(write)
        result.generated_outputs = sorted(gen)
        result.validation_profiles = sorted(profiles)
        return result


def build_index(root: Path) -> MaterialisationIndex:
    return MaterialisationIndex(root).build()
