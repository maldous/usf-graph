"""Deterministic sandbox enforcement.

Enforcement never relies on model compliance (build task §14). These pure
functions inspect what a worker actually produced/attempted:

* patch scope — a unified diff may only touch allowed write paths, never /usf,
  never the integration branch, never the secret file;
* secret leakage — token-shaped strings or references to the secret file;
* command allowlist — only vetted, read/local commands; never push/network/
  destructive commands.
"""

from __future__ import annotations

import re
import shlex

from .paths import ENV_FILE, USF_REPO

# Commands a worker may run inside its disposable clone. Deny list wins.
DEFAULT_ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "git",
        "python",
        "python3",
        "pytest",
        "ruff",
        "mypy",
        "node",
        "npm",
        "cat",
        "ls",
        "grep",
        "rg",
        "sed",
        "awk",
        "head",
        "tail",
        "diff",
        "find",
    }
)
DEFAULT_DENIED_COMMANDS: frozenset[str] = frozenset(
    {"curl", "wget", "nc", "ncat", "ssh", "scp", "rsync", "sudo", "dd", "mkfs", "telnet"}
)
# git subcommands that must never run inside a worker sandbox.
DENIED_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {"push", "remote", "fetch", "pull", "clone", "submodule", "config"}
)

_TOKEN_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxai-[A-Za-z0-9]{16,}\b"),
)


def parse_unified_diff_paths(patch: str) -> list[str]:
    """Extract target file paths from a git unified diff."""
    paths: set[str] = set()
    for line in patch.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            target = line[4:].strip()
            if target in ("/dev/null", ""):
                continue
            # Strip a/ or b/ prefixes.
            if target[:2] in ("a/", "b/"):
                target = target[2:]
            paths.add(target)
        elif line.startswith("diff --git "):
            parts = line.split()
            for p in parts[2:]:
                if p[:2] in ("a/", "b/"):
                    paths.add(p[2:])
    return sorted(paths)


def _is_under(path: str, root: str) -> bool:
    from pathlib import PurePosixPath

    try:
        PurePosixPath(path).relative_to(root)
        return True
    except ValueError:
        return False


def validate_patch_scope(patch: str, allowed_write_paths: list[str]) -> list[str]:
    """Return the list of scope violations for a patch.

    A path is a violation if it is not within the allowed write set, is absolute,
    escapes the repo (``..``), targets /usf, or targets the secret file.
    """
    violations: list[str] = []
    allowed = set(allowed_write_paths)
    for path in parse_unified_diff_paths(patch):
        if path.startswith("/"):
            violations.append(f"absolute path: {path}")
            continue
        if ".." in path.split("/"):
            violations.append(f"path escapes repo: {path}")
            continue
        if _is_under(path, str(USF_REPO).lstrip("/")):
            violations.append(f"targets /usf: {path}")
            continue
        if path not in allowed:
            violations.append(f"outside write scope: {path}")
    return violations


def scan_secrets(text: str) -> list[str]:
    """Return reasons the text appears to contain or reference secrets."""
    reasons: list[str] = []
    if str(ENV_FILE) in text or "/root/.env" in text:
        reasons.append("references the secret file path")
    for pat in _TOKEN_SHAPES:
        if pat.search(text):
            reasons.append("contains a token-shaped string")
            break
    return reasons


def check_command(
    command: str, *, allowed: frozenset[str] | None = None, denied: frozenset[str] | None = None
) -> tuple[bool, str]:
    """Validate a single shell command against the allow/deny policy."""
    allowed = allowed or DEFAULT_ALLOWED_COMMANDS
    denied = denied or DEFAULT_DENIED_COMMANDS
    try:
        tokens = shlex.split(command)
    except ValueError:
        return (False, "unparseable command")
    if not tokens:
        return (False, "empty command")
    prog = tokens[0].rsplit("/", 1)[-1]
    if prog in denied:
        return (False, f"denied command: {prog}")
    if prog not in allowed:
        return (False, f"command not on allowlist: {prog}")
    if prog == "git" and len(tokens) > 1:
        sub = tokens[1]
        if sub in DENIED_GIT_SUBCOMMANDS:
            return (False, f"denied git subcommand: {sub}")
    # Reject obvious shell escapes / network / destructive patterns.
    lowered = command.lower()
    for bad in ("rm -rf /", "> /root/.env", "/usf/.git", "http://", "https://"):
        if bad in lowered:
            return (False, f"blocked pattern: {bad}")
    return (True, "ok")


def assert_no_usf_paths(paths: list[str]) -> list[str]:
    """Return any paths that fall under /usf (must be empty)."""
    root = str(USF_REPO).lstrip("/")
    return [p for p in paths if _is_under(p.lstrip("/"), root)]
