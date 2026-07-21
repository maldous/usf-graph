"""Bounded, digest-bound semantic context pack (§4).

The orchestrator builds a compact, token-minimized context pack for a bounded
patch/analysis worker. The model NEVER accesses the repository or workspace: it
receives only this pack. Source is read from the FACTORY MIRROR at the packet's
exact ``base_head`` commit (never ``/usf`` or a working tree).

Layout (token discipline):
* a STABLE PREFIX — the shared semantic rule bundle, byte-identical across
  providers (maximizes prompt-cache reuse);
* a compact TASK DELTA — packet identity, objective, acceptance criteria,
  semantic subjects, authorized read/write paths, current blob digests, the
  strict result schema, required regeneration/validation commands, and the
  generated outputs that must not be edited directly;
* bounded SOURCE EXCERPTS — subject-specific RDF blocks, relevant SHACL shapes,
  SPARQL constraints, and test/fixture excerpts. Contents are included only when
  source egress is authorized for the target provider; otherwise only paths +
  blob digests are shared (a private-metadata projection).

One bounded context-expansion retry is supported via NEEDS_CONTEXT: the model may
name an already-authorized path/subject; the orchestrator adds ONE more bounded
excerpt and retries once. No arbitrary path requests, no filesystem access, no
unbounded loops.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import content_digest

_MAX_EXCERPTS = 8
_MAX_EXCERPT_LINES = 60
_MAX_EXCERPT_CHARS = 4000
_RDF_SUFFIXES = (".ttl", ".trig", ".nt", ".n3")
_SHACL_HINT = ("shape", "shacl")
_SPARQL_SUFFIXES = (".rq", ".sparql")
_TEST_HINT = ("test", "fixture")


def _read_blob(mirror: Path, commit: str, path: str) -> str | None:
    """Read a file's content from the factory mirror at a specific commit (never
    the working tree). Returns None if absent."""
    try:
        r = subprocess.run(
            ["git", "-C", str(mirror), "show", f"{commit}:{path}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return r.stdout


def _blob_digest(mirror: Path, commit: str, path: str) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(mirror), "rev-parse", f"{commit}:{path}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return None
    return ("git:" + r.stdout.strip()) if r.returncode == 0 else None


def _local_subject(subject: str) -> str:
    """The bare local name of an IRI/urn for cheap substring relevance."""
    for sep in ("#", "/", ":"):
        if sep in subject:
            subject = subject.rsplit(sep, 1)[-1]
    return subject


def _extract_subject_block(text: str, subjects: list[str]) -> str:
    """Prefix declarations + lines/blocks that mention any subject (or its local
    name), capped. Keeps @prefix/PREFIX lines so the RDF is interpretable."""
    lines = text.splitlines()
    prefixes = [ln for ln in lines if ln.strip().lower().startswith(("@prefix", "prefix "))]
    needles = set(subjects) | {_local_subject(s) for s in subjects}
    kept: list[str] = []
    for i, ln in enumerate(lines):
        if any(n and n in ln for n in needles):
            # include a small window around the match for statement context.
            for j in range(max(0, i - 1), min(len(lines), i + 4)):
                if lines[j] not in kept:
                    kept.append(lines[j])
    body = [*prefixes, "...", *kept] if kept else lines
    out = "\n".join(dict.fromkeys(body))
    if len(out) > _MAX_EXCERPT_CHARS:
        out = out[:_MAX_EXCERPT_CHARS] + "\n... [truncated]"
    return "\n".join(out.splitlines()[: _MAX_EXCERPT_LINES + len(prefixes) + 1])


def _classify(path: str) -> str:
    low = path.lower()
    if any(low.endswith(s) for s in _SPARQL_SUFFIXES):
        return "sparql"
    if any(h in low for h in _SHACL_HINT):
        return "shacl"
    if any(h in low for h in _TEST_HINT):
        return "test"
    if any(low.endswith(s) for s in _RDF_SUFFIXES):
        return "rdf"
    return "other"


@dataclass
class ContextPack:
    stable_prefix: str
    task_delta: dict[str, Any]
    excerpts: list[dict[str, Any]] = field(default_factory=list)
    egress_allowed: bool = False
    egress_reason: str = ""
    stable_prefix_digest: str = ""
    task_delta_digest: str = ""
    context_pack_digest: str = ""

    def render(self, contract: str = "") -> str:
        """The full prompt: stable prefix first (byte-identical across providers),
        then the compact task delta, then bounded excerpts (or a metadata note).
        ``contract`` (also stable) is placed inside the cacheable prefix region."""
        import json

        prefix = self.stable_prefix + ("\n\n" + contract if contract else "")
        parts = [prefix, "\n\nTASK:\n" + json.dumps(self.task_delta, sort_keys=True)]
        if self.egress_allowed and self.excerpts:
            parts.append("\n\nAUTHORIZED SOURCE EXCERPTS (bounded, snapshot-pinned):")
            for e in self.excerpts:
                parts.append(
                    f"\n# {e['path']} [{e['kind']}] {e.get('digest', '')}\n{e.get('content', '')}"
                )
        else:
            paths = [f"{e['path']} ({e.get('digest', '')})" for e in self.excerpts]
            parts.append(
                "\n\nSOURCE CONTENT WITHHELD (egress not authorized: "
                + (self.egress_reason or "external provider")
                + "). Available authorized paths + digests only:\n"
                + "\n".join(paths)
            )
        return "".join(parts)


def _relevant_paths(packet: Any, index: Any) -> list[tuple[str, str]]:
    """Ordered (path, kind) pairs relevant to the packet: authorized read/write
    paths first, then subject-specific paths from the materialisation index."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(p: str) -> None:
        if p and p not in seen:
            seen.add(p)
            out.append((p, _classify(p)))

    for p in list(packet.read_paths) + list(packet.write_paths):
        add(p)
    if index is not None:
        for subj in packet.semantic_subjects:
            entry = getattr(index, "entries", {}).get(subj)
            if entry is None:
                continue
            for p in [
                *entry.candidate_owners,
                *entry.related_paths,
                *entry.shapes,
                *entry.rules,
                *entry.tests,
            ]:
                add(p)
    return out


def build_context_pack(
    ctx: Any,
    packet: Any,
    *,
    egress_allowed: bool,
    egress_reason: str = "",
    index: Any = None,
    extra_paths: list[str] | None = None,
    result_schema: dict[str, Any] | None = None,
) -> ContextPack:
    """Build the bounded, digest-bound context pack for a packet from the factory
    mirror at ``packet.base_head``. ``egress_allowed`` gates whether source
    CONTENTS (vs paths + digests only) are included."""
    from .provider_eval import RULE_BUNDLE, RULE_BUNDLE_VERSION, rule_bundle_digest

    mirror = ctx.paths.mirror
    commit = packet.base_head

    task_delta = {
        "packetId": packet.packet_id,
        "obligationId": packet.obligation_id,
        "snapshotId": packet.snapshot_id,
        "authorityDigest": packet.authority_digest,
        "baseHead": packet.base_head,
        "objective": packet.objective,
        "taskClass": packet.task_class,
        "semanticSubjects": list(packet.semantic_subjects),
        "readPaths": list(packet.read_paths),
        "writePaths": list(packet.write_paths),
        "generatedOutputs": list(packet.generated_outputs),
        "doNotEditDirectly": list(packet.generated_outputs),
        "acceptanceCriteria": list(packet.acceptance_criteria),
        "requiredValidation": list(packet.required_validation),
        "inputDigests": dict(packet.input_digests),
        "ruleBundleVersion": RULE_BUNDLE_VERSION,
        "ruleBundleDigest": rule_bundle_digest(),
        "resultSchema": result_schema or {},
    }

    paths = _relevant_paths(packet, index)
    for p in extra_paths or []:
        if p not in {pp for pp, _ in paths}:
            paths.append((p, _classify(p)))

    excerpts: list[dict[str, Any]] = []
    for path, kind in paths[:_MAX_EXCERPTS]:
        digest = _blob_digest(mirror, commit, path)
        entry: dict[str, Any] = {"path": path, "kind": kind, "digest": digest or "unknown"}
        if egress_allowed and digest is not None:
            content = _read_blob(mirror, commit, path)
            if content is not None:
                entry["content"] = (
                    _extract_subject_block(content, list(packet.semantic_subjects))
                    if kind in ("rdf", "shacl")
                    else content[:_MAX_EXCERPT_CHARS]
                )
        excerpts.append(entry)

    stable_digest = rule_bundle_digest()
    delta_digest = content_digest(task_delta)
    pack_digest = content_digest(
        {
            "prefix": stable_digest,
            "delta": delta_digest,
            "excerpts": [e.get("digest") for e in excerpts],
        }
    )
    return ContextPack(
        stable_prefix=RULE_BUNDLE,
        task_delta=task_delta,
        excerpts=excerpts,
        egress_allowed=egress_allowed,
        egress_reason=egress_reason,
        stable_prefix_digest=stable_digest,
        task_delta_digest=delta_digest,
        context_pack_digest=pack_digest,
    )
