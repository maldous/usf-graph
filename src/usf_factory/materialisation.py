"""Semantic subject -> repository materialisation ownership (Phase 2).

Maps a semantic subject IRI to the repository surface that materialises it and,
crucially, distinguishes:

    candidate owner   a parsed RDF/OWL declaration in an owner-eligible file
    verified owner    a candidate SUPPORTED by explicit, digest-bound evidence:
                        - a USF layout/materialisation contract (via MCP),
                        - a generator input->output declaration,
                        - a manifest/registry ownership entry, or
                        - an append-only operator approval.

A parsed declaration ALONE never authorizes a semantic write scope. A shape,
fixture, observation/test datum, rule, or generated projection is never an owner
merely because it types a resource — only owner-eligible source files (ontology /
semantic-model definitions) can be candidate owners.

Parsing is a conservative, comment-aware, multi-line Turtle/TriG subset scanner
(prefix expansion, declaration detection across newlines, TriG named graphs,
reference-before-declaration). It never asserts semantic truth — the MCP
authority boundary does that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import content_digest

INDEX_VERSION = "mat-index-v2"

_RDF_SUFFIXES = (".ttl", ".trig", ".turtle", ".nt", ".n3")
_PREFIX_RE = re.compile(r"@?prefix\s+([A-Za-z][\w.\-]*)?:\s*<([^>]*)>\s*\.?", re.IGNORECASE)
_SPARQL_PREFIX_RE = re.compile(r"PREFIX\s+([A-Za-z][\w.\-]*)?:\s*<([^>]*)>", re.IGNORECASE)
_TERM = r"(?:<[^>]+>|[A-Za-z][\w.\-]*:[\w.\-]+)"
# A subject DECLARATION: <subject> ... a|rdf:type (subject and predicate may be
# separated by newlines/whitespace, as in multi-line Turtle and TriG bodies).
_DECL_RE = re.compile(rf"({_TERM})\s+(?:a|rdf:type)\s", re.DOTALL)
_TOKEN_RE = re.compile(_TERM)

# Only these file kinds can be CANDIDATE owners. Shapes/rules/tests/fixtures/
# generated files that merely type a resource are never owners.
_OWNER_ELIGIBLE_KINDS = frozenset({"ontology"})


@dataclass
class MaterialisationEntry:
    subject: str
    candidate_owners: list[str] = field(default_factory=list)
    verified_owner: str | None = None
    verification_kind: str | None = None  # layout-contract | generator | manifest | operator
    related_paths: list[str] = field(default_factory=list)
    shapes: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    generated_outputs: list[str] = field(default_factory=list)
    validation_profiles: list[str] = field(default_factory=list)
    method: str = "inferred"  # parsed-candidate | verified | ambiguous | inferred
    confidence: float = 0.0

    @property
    def owner_path(self) -> str | None:
        """Back-compat: the owner path is the VERIFIED one (never a bare candidate)."""
        return self.verified_owner

    @property
    def verified(self) -> bool:
        return self.verified_owner is not None


@dataclass
class ScopeResult:
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    generated_outputs: list[str] = field(default_factory=list)
    validation_profiles: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)  # no verified owner
    ambiguous: list[str] = field(default_factory=list)  # >1 candidate, none verified

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


def _strip_comments(text: str) -> str:
    """Remove Turtle/SPARQL line comments, preserving ``#`` inside <IRIs>."""
    out_lines = []
    for line in text.splitlines():
        in_iri = False
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == "<":
                in_iri = True
            elif ch == ">":
                in_iri = False
            elif ch == "#" and not in_iri:
                cut = i
                break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def _classify_path(rel: str) -> tuple[str, list[str]]:
    """Return (kind, validation_profiles) by path/naming heuristics. Order matters:
    a shape/fixture/generated file is classified as such even if it ends in .ttl,
    so it can never be treated as an ontology owner."""
    low = rel.lower()
    base = low.rsplit("/", 1)[-1]
    if any(seg in low for seg in ("/generated/", "/derived/", "generated-", "derived-")):
        return "generated", []
    if (
        "/fixtures/" in low
        or "fixture" in base
        or "/tests/" in low
        or "/test/" in low
        or base.startswith("test_")
    ):
        return "test", ["negative-fixtures"]
    if "/shapes/" in low or "shacl" in low or low.endswith(".shacl.ttl"):
        return "shape", ["syntax-parse", "shacl"]
    if low.endswith((".rq", ".sparql")) or "/queries/" in low or "/rules/" in low:
        return "rule", ["syntax-parse", "integrity-sparql"]
    if "manifest" in base or "registry" in base:
        return "manifest", ["manifest-check"]
    if low.endswith(_RDF_SUFFIXES):
        return "ontology", ["syntax-parse", "shacl"]
    return "other", []


class MaterialisationIndex:
    def __init__(self, root: Path, *, index_version: str = INDEX_VERSION) -> None:
        self.root = Path(root)
        self.index_version = index_version
        self.entries: dict[str, MaterialisationEntry] = {}
        self.source_digest: str = ""
        self.source_commit: str = ""
        self.snapshot_bound: bool = False
        self._candidate_owners: dict[str, set[str]] = {}

    # ---- build ---------------------------------------------------------- #

    def build(
        self, include: tuple[str, ...] = (*_RDF_SUFFIXES, ".rq", ".sparql")
    ) -> MaterialisationIndex:
        """Working-tree build (analysis-only, never a write contract)."""
        files = sorted(
            p
            for p in self.root.rglob("*")
            if p.is_file()
            and ".git/" not in str(p.relative_to(self.root)) + "/"
            and p.suffix.lower() in include
        )
        contents = {}
        for path in files:
            rel = str(path.relative_to(self.root))
            try:
                contents[rel] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return self._index_all(contents)

    def build_from_git(
        self, commit: str, include: tuple[str, ...] = (*_RDF_SUFFIXES, ".rq", ".sparql")
    ) -> MaterialisationIndex:
        """Snapshot-bound build from the git object store at an exact commit
        (works on a bare mirror; contract-grade)."""
        import subprocess

        ls = subprocess.run(
            ["git", "-C", str(self.root), "ls-tree", "-r", "--name-only", commit],
            capture_output=True,
            text=True,
        )
        if ls.returncode != 0:
            raise ValueError(f"cannot list tree at {commit}: {ls.stderr.strip()[:200]}")
        files = sorted(p for p in ls.stdout.splitlines() if Path(p).suffix.lower() in include)
        contents = {}
        for rel in files:
            show = subprocess.run(
                ["git", "-C", str(self.root), "show", f"{commit}:{rel}"],
                capture_output=True,
                text=True,
            )
            if show.returncode == 0:
                contents[rel] = show.stdout
        self._index_all(contents)
        self.source_commit = commit
        self.snapshot_bound = True
        return self

    def _index_all(self, contents: dict[str, str]) -> MaterialisationIndex:
        """Multi-pass: (1) declarations -> candidate owners + subject set;
        (2) references across all files -> related; then finalise."""
        file_digests: dict[str, str] = {}
        # Pass 1: declarations (candidate owners, owner-eligible files only).
        for rel, text in sorted(contents.items()):
            file_digests[rel] = content_digest({"path": rel, "text": text})
            self._index_declarations(rel, text)
        # Pass 2: references + artifact associations across ALL files.
        for rel, text in sorted(contents.items()):
            self._index_references(rel, text)
        self._finalise(file_digests)
        return self

    def _prefixes(self, text: str) -> dict[str, str]:
        prefixes: dict[str, str] = {}
        for m in _PREFIX_RE.finditer(text):
            prefixes[m.group(1) or ""] = m.group(2)
        for m in _SPARQL_PREFIX_RE.finditer(text):
            prefixes[m.group(1) or ""] = m.group(2)
        return prefixes

    def _index_declarations(self, rel: str, text: str) -> None:
        kind, _profiles = _classify_path(rel)
        clean = _strip_comments(text)
        prefixes = self._prefixes(clean)
        for m in _DECL_RE.finditer(clean):
            iri = _expand(m.group(1), prefixes)
            if not iri:
                continue
            entry = self.entries.setdefault(iri, MaterialisationEntry(subject=iri))
            # Only owner-eligible files contribute a CANDIDATE owner.
            if kind in _OWNER_ELIGIBLE_KINDS:
                self._candidate_owners.setdefault(iri, set()).add(rel)
            if rel not in entry.related_paths:
                entry.related_paths.append(rel)

    def _index_references(self, rel: str, text: str) -> None:
        kind, profiles = _classify_path(rel)
        clean = _strip_comments(text)
        prefixes = self._prefixes(clean)
        for tok in _TOKEN_RE.findall(clean):
            iri = _expand(tok, prefixes)
            if iri and iri in self.entries:
                self._attach(self.entries[iri], rel, kind, profiles)

    def _attach(self, e: MaterialisationEntry, rel: str, kind: str, profiles: list[str]) -> None:
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

    def _finalise(self, file_digests: dict[str, str]) -> None:
        for subj, entry in self.entries.items():
            owners = sorted(self._candidate_owners.get(subj, set()))
            entry.candidate_owners = owners
            if len(owners) == 1:
                entry.method = "parsed-candidate"
                entry.confidence = 0.6  # a candidate, NOT verified
            elif len(owners) > 1:
                entry.method = "ambiguous"
                entry.confidence = 0.3
            else:
                entry.method = "inferred"
                entry.confidence = 0.2
            entry.related_paths = sorted(set(entry.related_paths))
            entry.validation_profiles = sorted(set(entry.validation_profiles))
        self.source_digest = content_digest(
            {"version": self.index_version, "files": dict(sorted(file_digests.items()))}
        )

    # ---- verification (evidence reconciliation) ------------------------- #

    def apply_ownership_evidence(self, evidence: list[dict]) -> None:
        """Mark verified owners from explicit, digest-bound ownership evidence.

        ``evidence`` rows (from the ownership_evidence store or a live contract)
        must have subject, owner_path, evidence_kind, verified=True, and — for
        contract-grade use — a repository_commit matching this index. A row whose
        commit does not match this snapshot is IGNORED (stale)."""
        for ev in evidence:
            if not ev.get("verified"):
                continue
            if self.source_commit and ev.get("repository_commit") not in ("", self.source_commit):
                continue  # stale: bound to a different commit
            subj = str(ev.get("subject") or "")
            path = str(ev.get("owner_path") or "")
            entry = self.entries.get(subj)
            if entry is None or not path:
                continue
            # Evidence may only VERIFY a path that is an actual candidate owner
            # (or explicitly operator-approved, which is authoritative on its own).
            if ev.get("evidence_kind") == "operator" or path in entry.candidate_owners:
                entry.verified_owner = path
                entry.verification_kind = ev.get("evidence_kind")
                entry.method = "verified"
                entry.confidence = 0.98

    # ---- query ---------------------------------------------------------- #

    def resolve(self, iri: str) -> MaterialisationEntry | None:
        return self.entries.get(iri)

    def candidates(self) -> list[MaterialisationEntry]:
        return [e for e in self.entries.values() if e.candidate_owners and not e.verified]

    def verified(self) -> list[MaterialisationEntry]:
        return [e for e in self.entries.values() if e.verified]

    def affected_by(self, path: str) -> list[str]:
        return sorted(
            s
            for s, e in self.entries.items()
            if path == e.verified_owner or path in e.candidate_owners or path in e.related_paths
        )

    def derive_scope(self, subjects: list[str], *, authorize_writes: bool = False) -> ScopeResult:
        """Read/validation scope for a set of subjects. A write scope is granted
        ONLY for subjects with a VERIFIED (evidence-backed) owner, and only when
        ``authorize_writes`` is set. Candidate-only and ambiguous subjects yield
        read context but never a write."""
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
            read.update(e.related_paths)
            read.update(e.candidate_owners)
            gen.update(e.generated_outputs)
            profiles.update(e.validation_profiles)
            if e.verified and e.verified_owner:
                if authorize_writes:
                    write.add(e.verified_owner)
                read.add(e.verified_owner)
            elif len(e.candidate_owners) > 1:
                result.ambiguous.append(subj)
            else:
                result.unresolved.append(subj)  # candidate-only or none => no write
        result.read_paths = sorted(read)
        result.write_paths = sorted(write)
        result.generated_outputs = sorted(gen)
        result.validation_profiles = sorted(profiles)
        return result


def build_index(root: Path) -> MaterialisationIndex:
    """Working-tree build: analysis-only, never contract-grade."""
    return MaterialisationIndex(root).build()


def build_index_at(repo: Path, commit: str) -> MaterialisationIndex:
    """Snapshot-bound build from the git object store at ``commit``."""
    return MaterialisationIndex(repo).build_from_git(commit)
