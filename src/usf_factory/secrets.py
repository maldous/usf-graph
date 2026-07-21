"""Credential handling: allowlist, alias normalization, conflict detection, and
redaction.

This module NEVER emits a credential value. Every public function and data
structure exposes only variable *names* and booleans. The single place a value
is materialized is when writing ``/root/.env`` atomically, and that path does no
logging.

Design points
-------------
* Only an exact allowlist of canonical model-provider variables is importable.
* Source aliases are normalized to canonical names with documented precedence.
* If two non-empty aliases for the same canonical variable *differ*, that
  variable's import is stopped and reported as a conflict (no value printed).
* Excluded variables (Stardog, unrelated services) are never imported.
* ``AIS_API_KEY`` is recorded as an unmapped candidate by name only.
* GitHub Models is not admitted from a general token until a probe proves the
  Models permission (handled by :func:`github_models_write_policy`).
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Canonical variables and alias table (DESIGN.md build task §5.1 / §5.2).
# --------------------------------------------------------------------------- #

# Ordered so provenance is stable. The canonical name is always the first alias.
ALIAS_TABLE: dict[str, list[str]] = {
    "OPENAI_API_KEY": ["OPENAI_API_KEY"],
    "OPENROUTER_API_KEY": ["OPENROUTER_API_KEY", "OPENROUTER_TOKEN"],
    "GROQ_API_KEY": ["GROQ_API_KEY", "GROQ_TOKEN"],
    "MISTRAL_API_KEY": ["MISTRAL_API_KEY", "MISTRAL_TOKEN"],
    "GEMINI_API_KEY": ["GEMINI_API_KEY", "GOOGLE_GEMINI_API_KEY", "GEMINI_TOKEN"],
    "SAMBANOVA_API_KEY": ["SAMBANOVA_API_KEY", "SAMBANOVA_TOKEN"],
    "GITHUB_MODELS_TOKEN": [
        "GITHUB_MODELS_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
    ],
    "GITHUB_PERSONAL_ACCESS_TOKEN": ["GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN"],
    "HF_TOKEN": ["HF_TOKEN", "HUGGING_TOKEN", "HUGGING_FACE_READ_TOKEN"],
    "FIREWORKS_API_KEY": ["FIREWORKS_API_KEY", "FIREWORKS_KEY"],
    "TOGETHER_API_KEY": ["TOGETHER_API_KEY", "TOGETHER_KEY"],
    "DEEPSEEK_API_KEY": ["DEEPSEEK_API_KEY", "DEEPSEEK_TOKEN"],
    "CEREBRAS_API_KEY": ["CEREBRAS_API_KEY", "CEREBRAS_TOKEN", "CERABRAS_TOKEN"],
    "ARCEE_TOKEN": ["ARCEE_TOKEN", "ARCEEAI_KEY"],
    "OPENAI_API_KEY_ALT": [],  # placeholder removed below; see CANONICAL_VARS
    "OLLAMA_API_KEY": ["OLLAMA_API_KEY"],
    "XAI_API_KEY": ["XAI_API_KEY"],
    "ANTHROPIC_API_KEY": ["ANTHROPIC_API_KEY"],
}
# Drop the placeholder used only to keep the literal readable.
del ALIAS_TABLE["OPENAI_API_KEY_ALT"]

# The canonical variables the factory will store in /root/.env when a usable
# source exists. XAI_API_KEY and ANTHROPIC_API_KEY are recognized but their
# providers stay disabled until a value is supplied; they are stored if present.
CANONICAL_VARS: tuple[str, ...] = tuple(ALIAS_TABLE.keys())

# Canonicals whose GitHub sources intentionally overlap: use *precedence* (first
# non-empty alias in order wins) instead of strict conflict detection, because
# GITHUB_TOKEN / GITHUB_PERSONAL_ACCESS_TOKEN legitimately feed two canonicals.
PRECEDENCE_CANONICALS: frozenset[str] = frozenset(
    {"GITHUB_MODELS_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN"}
)

# Optional canonicals — absence is not a defect.
OPTIONAL_CANONICALS: frozenset[str] = frozenset(
    {"OLLAMA_API_KEY", "XAI_API_KEY", "ANTHROPIC_API_KEY"}
)

# Explicitly excluded — never imported into /root/.env (build task §5.3), plus
# all Stardog credentials (the factory uses the /usf MCP boundary instead).
EXCLUDED_VARS: frozenset[str] = frozenset(
    {
        "STARDOG_TOKEN",
        "STARDOG_SERVER",
        "STARDOG_DATABASE",
        "STARDOG_USERNAME",
        "STARDOG_PASSWORD",
        "APPLE_APP_STORE_CONNECT_KEY_ID",
        "ATLASSIAN_TOKEN",
        "BREVO_SMTP_KEY",
        "CONTEXT7_API_KEY",
        "DISCORD_BOT_TOKEN",
        "ELEVENLABS_API_KEY",
        "GOOGLE_PLACES_API_KEY",
        "INWORLD_API_KEY",
        "JIRA_TOKEN",
        "LINEAR_API_KEY",
        "LINKUP_API_KEY",
        "MSMTP_KEY",
        "NETLIFY_API_TOKEN",
        "NUCLEI_TOKEN",
        "OPENSKY_CLIENT_ID",
        "OPENSKY_CLIENT_SECRET",
        "PAPERLY_SENTRY_ENG_TOKEN",
        "PAPERLY_SENTRY_ORG_TOKEN",
        "SENTRY_AUTH_TOKEN",
        "SNYK_TOKEN",
        "SONARQUBE_TOKEN",
        "SONAR_TOKEN",
        "SSH_CLIENT",
        "UPTIMEROBOT_API_KEY",
        "WPSCAN_TOKEN",
    }
)

# Recorded by name only; never imported (provider unknown).
UNMAPPED_CANDIDATES: frozenset[str] = frozenset({"AIS_API_KEY"})


@dataclass
class ResolvedVar:
    """A resolved canonical variable — names only, never the value."""

    canonical: str
    provenance_alias: str
    is_optional: bool


@dataclass
class Normalization:
    """Result of normalizing a set of source variables.

    ``_values`` holds materialized secret values solely so the caller can write
    them to ``/root/.env``. It is excluded from ``__repr__`` and never logged.
    """

    resolved: dict[str, ResolvedVar] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    excluded_present: list[str] = field(default_factory=list)
    unmapped_candidates: list[str] = field(default_factory=list)
    _values: dict[str, str] = field(default_factory=dict, repr=False)

    def imported_names(self) -> list[str]:
        return sorted(self.resolved.keys())

    def provenance(self) -> dict[str, str]:
        return {c: r.provenance_alias for c, r in sorted(self.resolved.items())}

    def value_of(self, canonical: str) -> str:
        """Return the secret value (for writing only). Never log the result."""
        return self._values[canonical]

    def __repr__(self) -> str:  # pragma: no cover - trivial, but must be safe
        return (
            "Normalization("
            f"resolved={self.imported_names()}, "
            f"conflicts={sorted(self.conflicts)}, "
            f"missing={sorted(self.missing)}, "
            f"excluded_present={sorted(self.excluded_present)}, "
            f"unmapped_candidates={sorted(self.unmapped_candidates)})"
        )


def _nonempty(value: str | None) -> bool:
    return value is not None and value.strip() != ""


def normalize(sources: Mapping[str, str]) -> Normalization:
    """Normalize source variables into canonical model-provider variables.

    ``sources`` maps arbitrary environment names to values. Only allowlisted
    canonicals are considered; excluded and unmapped names are reported by name.
    """
    result = Normalization()

    present = {k: v for k, v in sources.items() if _nonempty(v)}

    # Report excluded and unmapped candidates by name (no values).
    result.excluded_present = sorted(n for n in present if n in EXCLUDED_VARS)
    result.unmapped_candidates = sorted(n for n in present if n in UNMAPPED_CANDIDATES)

    for canonical, aliases in ALIAS_TABLE.items():
        is_optional = canonical in OPTIONAL_CANONICALS

        if canonical in PRECEDENCE_CANONICALS:
            # First non-empty alias in precedence order wins; no conflict.
            chosen: str | None = None
            for alias in aliases:
                if _nonempty(present.get(alias)):
                    chosen = alias
                    break
            if chosen is None:
                result.missing.append(canonical)
                continue
            result.resolved[canonical] = ResolvedVar(canonical, chosen, is_optional)
            result._values[canonical] = present[chosen].strip()
            continue

        # Strict conflict detection: distinct non-empty values across aliases.
        found: list[tuple[str, str]] = [
            (alias, present[alias].strip()) for alias in aliases if _nonempty(present.get(alias))
        ]
        distinct_values = {v for _, v in found}
        if not found:
            result.missing.append(canonical)
        elif len(distinct_values) > 1:
            # Ambiguous — stop this variable's import and report the conflict.
            result.conflicts.append(canonical)
        else:
            provenance_alias = found[0][0]
            result.resolved[canonical] = ResolvedVar(canonical, provenance_alias, is_optional)
            result._values[canonical] = found[0][1]

    result.missing = sorted(result.missing)
    result.conflicts = sorted(result.conflicts)
    return result


def github_models_write_policy(norm: Normalization) -> tuple[bool, str]:
    """Decide whether GITHUB_MODELS_TOKEN should be *written* to /root/.env.

    A general GitHub token does not imply Models permission, so the token is
    only written when it came from an explicit ``GITHUB_MODELS_TOKEN`` source.
    Otherwise the PAT remains available (under GITHUB_PERSONAL_ACCESS_TOKEN) for
    a probe-gated runtime fallback, and github-models stays unadmitted.

    Returns ``(write, reason)``.
    """
    rv = norm.resolved.get("GITHUB_MODELS_TOKEN")
    if rv is None:
        return (False, "no source for GITHUB_MODELS_TOKEN")
    if rv.provenance_alias == "GITHUB_MODELS_TOKEN":
        return (True, "explicit GITHUB_MODELS_TOKEN source")
    return (
        False,
        f"derived from general token ({rv.provenance_alias}); requires Models-permission probe",
    )


def select_for_write(norm: Normalization) -> list[str]:
    """Canonical variable names that should be persisted to /root/.env.

    Applies the GitHub Models admission policy. Empty/optional-absent vars are
    naturally excluded because they are not in ``norm.resolved``.
    """
    names = set(norm.resolved.keys())
    write_gm, _ = github_models_write_policy(norm)
    if not write_gm:
        names.discard("GITHUB_MODELS_TOKEN")
    return sorted(names)


# --------------------------------------------------------------------------- #
# Parsing sources.
# --------------------------------------------------------------------------- #

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_env_file(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines (dotenv-ish). Comments and blanks ignored."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _ENV_LINE.match(raw)
        if not m:
            continue
        out[m.group(1)] = _strip_quotes(m.group(2))
    return out


def parse_env0(data: bytes) -> dict[str, str]:
    """Parse NUL-delimited ``KEY=VALUE`` records (from ``env -0``)."""
    out: dict[str, str] = {}
    for chunk in data.split(b"\x00"):
        if not chunk:
            continue
        try:
            record = chunk.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "=" not in record:
            continue
        key, _, value = record.partition("=")
        key = key.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            out[key] = value
    return out


# --------------------------------------------------------------------------- #
# Writing /root/.env atomically at mode 0600. No logging of values.
# --------------------------------------------------------------------------- #


def render_env_content(norm: Normalization, names: Iterable[str]) -> str:
    """Render the dotenv content for the given canonical names.

    A stable header (no timestamps) keeps the file byte-reproducible for a fixed
    credential set, which is friendly to prompt-prefix caching and diffing.
    """
    header = (
        "# usf-factory model-provider credentials.\n"
        "# Managed by scripts/import-provider-env.py. Do NOT edit by hand.\n"
        "# Owner root, mode 0600. Never printed, logged, committed, or in SQLite.\n"
    )
    lines = [f"{name}={norm.value_of(name)}" for name in sorted(names)]
    return header + "\n".join(lines) + ("\n" if lines else "")


def write_env_file(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path`` with mode 0600.

    Writes to a temp file in the same directory then ``os.replace`` for
    atomicity. The temp file is created with 0600 from the start.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    tmp_path = Path(tmp)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        tmp_path.replace(path)
        path.chmod(0o600)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def load_env_file(path: Path) -> dict[str, str]:
    """Load a dotenv file into a dict. Returns empty dict if missing."""
    if not path.exists():
        return {}
    return parse_env_file(path.read_text(encoding="utf-8"))


def load_allowlisted_env(path: Path) -> dict[str, str]:
    """Load ONLY allowlisted canonical variables from an env file.

    Even if the file contains extra (excluded) variables, the factory never
    reads or exposes them. Returns canonical name -> value.
    """
    raw = load_env_file(path)
    return {k: v for k, v in raw.items() if k in ALIAS_TABLE and _nonempty(v)}


# --------------------------------------------------------------------------- #
# Redaction — defense in depth for logs, reports, SQLite, and stdout.
# --------------------------------------------------------------------------- #

_REDACTED = "[REDACTED]"

# Heuristic patterns for common provider token shapes (defense in depth). We are
# conservative to avoid scrubbing legitimate content like sha256 digests.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\br8_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxai-[A-Za-z0-9]{16,}\b"),
)


class Redactor:
    """Scrubs known secret values and token-shaped strings from text.

    Load exact values once at startup (from ``/root/.env``); thereafter any
    string routed through :meth:`scrub` has those exact values removed, plus any
    token-shaped substrings as a heuristic backstop.
    """

    def __init__(self, values: Iterable[str] = ()) -> None:
        self._values: list[str] = sorted(
            {v for v in values if v and len(v) >= 6}, key=len, reverse=True
        )

    def add_values(self, values: Iterable[str]) -> None:
        merged = set(self._values) | {v for v in values if v and len(v) >= 6}
        self._values = sorted(merged, key=len, reverse=True)

    def scrub(self, text: str) -> str:
        if not text:
            return text
        out = text
        for value in self._values:  # exact known secrets first (longest first)
            if value in out:
                out = out.replace(value, _REDACTED)
        for pat in _TOKEN_PATTERNS:
            out = pat.sub(_REDACTED, out)
        return out


_GLOBAL_REDACTOR = Redactor()


def global_redactor() -> Redactor:
    return _GLOBAL_REDACTOR


def install_redaction_from_env(path: Path) -> None:
    """Load exact secret values from ``path`` into the global redactor.

    Only canonical model-provider values are loaded (allowlisted). Called once
    during runtime setup so any accidental value in a log/report is scrubbed.
    """
    values = load_allowlisted_env(path).values()
    _GLOBAL_REDACTOR.add_values(values)


def redact(text: str) -> str:
    """Scrub secrets from ``text`` using the global redactor."""
    return _GLOBAL_REDACTOR.scrub(text)
