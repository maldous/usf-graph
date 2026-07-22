"""Deterministic GitHub delivery (build task §13).

The COORDINATOR (not a model) carries an accepted, validated change into the
``usf-graph`` remote: a clean factory-owned clone, the effective diff (re-derived
from Git), a factory branch, a commit carrying obligation/authority/validation/
model-attribution trailers, a push (never force), a draft PR, a wait for required
checks, a reviewed-head==checked-head confirmation, and a gated merge.

No model ever receives a GitHub credential: every command runs in a subprocess
whose environment the coordinator controls; the model side of the factory only
ever sees bounded metadata. All operations are pure command construction +
output parsing, so they can be driven by a fake runner in tests and by real
``git``/``gh`` in production without changing the coordinator logic.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class CommandResult:
    ok: bool
    code: int
    out: str
    err: str


class CommandRunner(Protocol):
    def run(
        self,
        args: Sequence[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 600.0,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Real command runner: no shell, captured output, bounded timeout."""

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 600.0,
    ) -> CommandResult:
        try:
            p = subprocess.run(
                list(args),
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return CommandResult(ok=False, code=-1, out="", err=str(exc))
        return CommandResult(ok=p.returncode == 0, code=p.returncode, out=p.stdout, err=p.stderr)


def format_trailers(trailers: dict[str, str]) -> str:
    """Git commit trailers (Key: value), one per line, deterministically ordered."""
    return "\n".join(f"{k}: {v}" for k, v in trailers.items())


class GitHubDelivery:
    """Coordinator-owned Git/GitHub operations against a writable usf-graph clone.

    ``origin_url`` is the pushable remote (a real https URL in production, or a
    local bare repo path in tests). Credentials are supplied by the environment
    the runner inherits — never passed through a model.
    """

    def __init__(
        self,
        *,
        origin_url: str,
        runner: CommandRunner | None = None,
        env: dict[str, str] | None = None,
        author_name: str = "usf-factory",
        author_email: str = "factory@usf.local",
    ) -> None:
        self.origin_url = origin_url
        self.runner = runner or SubprocessRunner()
        self.env = env
        self.author_name = author_name
        self.author_email = author_email

    # ---- git plumbing --------------------------------------------------- #

    def _git(self, clone: Path, *args: str, timeout: float = 300.0) -> CommandResult:
        return self.runner.run(
            ["git", "-C", str(clone), *args], env=self.env, timeout=timeout
        )

    def clone_writable(self, dest: Path, base_head: str) -> CommandResult:
        """Create a clean factory-owned clone of the writable remote and check out
        the exact base commit (detached). Fails closed on any git error."""
        if dest.exists():
            return CommandResult(False, 1, "", f"destination already exists: {dest}")
        r = self.runner.run(["git", "clone", self.origin_url, str(dest)], env=self.env, timeout=600.0)
        if not r.ok:
            return r
        self._git(dest, "config", "user.name", self.author_name)
        self._git(dest, "config", "user.email", self.author_email)
        return self._git(dest, "checkout", base_head)

    def apply_effective_diff(self, clone: Path, diff_text: str, *, patch_path: Path) -> CommandResult:
        """Apply the accepted effective diff to the clone's index+worktree. The diff
        is written to ``patch_path`` and applied with ``git apply --index``."""
        patch_path.write_text(diff_text, encoding="utf-8")
        return self._git(clone, "apply", "--index", str(patch_path))

    def write_files(self, clone: Path, files: dict[str, str]) -> CommandResult:
        """Materialise evidence/record files (path -> content) into the clone and
        stage them — used for compact-evidence deliveries with no source diff."""
        for rel, content in files.items():
            target = clone / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return self._git(clone, "add", *sorted(files))

    def rederive_diff(self, clone: Path) -> str:
        """The staged diff re-derived from Git (the authoritative change, not the
        model's claimed patch)."""
        return self._git(clone, "diff", "--cached").out

    def create_branch(self, clone: Path, branch: str) -> CommandResult:
        return self._git(clone, "checkout", "-b", branch)

    def commit_with_trailers(
        self, clone: Path, subject: str, body: str, trailers: dict[str, str]
    ) -> tuple[CommandResult, str]:
        """Commit staged changes with provenance trailers; return (result, sha)."""
        message = f"{subject}\n\n{body}\n\n{format_trailers(trailers)}".strip() + "\n"
        r = self._git(clone, "commit", "-m", message)
        if not r.ok:
            return r, ""
        head = self._git(clone, "rev-parse", "HEAD")
        return head, head.out.strip()

    def push_branch(self, clone: Path, branch: str, *, allow_force: bool = False) -> CommandResult:
        """Push the branch to origin. NEVER force-pushes unless explicitly allowed
        (the coordinator only ever passes allow_force=False)."""
        args = ["push", "--set-upstream", "origin", branch]
        if allow_force:
            args.insert(1, "--force")
        return self._git(clone, *args, timeout=600.0)

    # ---- gh (pull requests) --------------------------------------------- #

    def open_draft_pr(
        self, clone: Path, *, base: str, head: str, title: str, body: str
    ) -> tuple[CommandResult, int | None, str]:
        """Open a DRAFT PR via gh; return (result, number, url)."""
        r = self.runner.run(
            [
                "gh", "pr", "create", "--draft", "--base", base, "--head", head,
                "--title", title, "--body", body,
            ],
            cwd=str(clone),
            env=self.env,
            timeout=300.0,
        )
        if not r.ok:
            return r, None, ""
        url = r.out.strip().splitlines()[-1] if r.out.strip() else ""
        number = self._pr_number(clone, head)
        return r, number, url

    def _pr_number(self, clone: Path, head: str) -> int | None:
        r = self.runner.run(
            ["gh", "pr", "view", head, "--json", "number", "-q", ".number"],
            cwd=str(clone),
            env=self.env,
            timeout=120.0,
        )
        try:
            return int(r.out.strip())
        except (ValueError, AttributeError):
            return None

    def wait_for_checks(self, clone: Path, pr: int, *, timeout: float = 900.0) -> CommandResult:
        """Block until required checks conclude (gh pr checks --watch). A non-zero
        exit => checks failed/aborted; the coordinator treats that as not-passed."""
        return self.runner.run(
            ["gh", "pr", "checks", str(pr), "--watch", "--required"],
            cwd=str(clone),
            env=self.env,
            timeout=timeout,
        )

    def pr_head_sha(self, clone: Path, pr: int) -> str:
        r = self.runner.run(
            ["gh", "pr", "view", str(pr), "--json", "headRefOid", "-q", ".headRefOid"],
            cwd=str(clone),
            env=self.env,
            timeout=120.0,
        )
        return r.out.strip()

    def mark_ready(self, clone: Path, pr: int) -> CommandResult:
        return self.runner.run(
            ["gh", "pr", "ready", str(pr)], cwd=str(clone), env=self.env, timeout=120.0
        )

    def merge_pr(self, clone: Path, pr: int, *, method: str = "squash") -> tuple[CommandResult, str]:
        """Merge the PR (no force). Returns (result, merge_commit_sha)."""
        r = self.runner.run(
            ["gh", "pr", "merge", str(pr), f"--{method}", "--delete-branch"],
            cwd=str(clone),
            env=self.env,
            timeout=300.0,
        )
        if not r.ok:
            return r, ""
        v = self.runner.run(
            ["gh", "pr", "view", str(pr), "--json", "mergeCommit", "-q", ".mergeCommit.oid"],
            cwd=str(clone),
            env=self.env,
            timeout=120.0,
        )
        return r, v.out.strip()

    def pr_state(self, clone: Path, pr: int) -> dict[str, object]:
        """Reconciliation helper: the PR's current state/merge facts, or {} when
        unknown — lets a restart discover whether a side effect already happened."""
        r = self.runner.run(
            ["gh", "pr", "view", str(pr), "--json", "state,merged,mergeCommit,headRefOid"],
            cwd=str(clone),
            env=self.env,
            timeout=120.0,
        )
        if not r.ok:
            return {}
        try:
            return dict(json.loads(r.out))
        except (ValueError, TypeError):
            return {}
