"""Repository isolation from /usf.

The chain (build task §2):

    read-only fetch from /usf
    -> factory-owned bare mirror outside /usf
    -> disposable clone per packet
    -> patch/result artifact
    -> centralized integration clone

Invariants enforced here:

* We NEVER write to /usf. Reads use ``--no-optional-locks`` so git never takes
  the index lock or rewrites /usf/.git. The mirror is cloned with
  ``--no-hardlinks`` so it shares no objects/alternates with /usf.
* We NEVER create a worktree registered under /usf/.git/worktrees. Disposable
  clones live under the factory-owned workspaces directory.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .canonical import digest_text
from .errors import IsolationViolationError
from .paths import USF_REPO, FactoryPaths


@dataclass
class GitResult:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def _git(args: list[str], cwd: Path | None = None, timeout: float = 120.0) -> GitResult:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return GitResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())


class RepoIsolation:
    def __init__(self, paths: FactoryPaths, usf_repo: Path | None = None) -> None:
        self.paths = paths
        self.usf_repo = usf_repo or USF_REPO

    # ---- guards --------------------------------------------------------- #

    def assert_not_usf(self, path: Path) -> None:
        """Refuse any path inside /usf (defense in depth)."""
        try:
            path.resolve().relative_to(self.usf_repo.resolve())
        except ValueError:
            return
        raise IsolationViolationError(f"refusing to operate inside /usf: {path}")

    def assert_no_factory_worktrees(self) -> list[str]:
        """Return any worktrees registered under /usf/.git/worktrees.

        The factory must never create one; this is a verification hook.
        """
        wt = self.usf_repo / ".git" / "worktrees"
        if not wt.is_dir():
            return []
        return [p.name for p in wt.iterdir() if p.is_dir()]

    # ---- read-only inspection of /usf ----------------------------------- #

    def usf_head(self) -> str:
        r = _git(["--no-optional-locks", "-C", str(self.usf_repo), "rev-parse", "HEAD"])
        if not r.ok:
            raise IsolationViolationError(f"cannot read /usf HEAD: {r.err}")
        return r.out

    def usf_branch(self) -> str:
        r = _git(
            ["--no-optional-locks", "-C", str(self.usf_repo), "rev-parse", "--abbrev-ref", "HEAD"]
        )
        return r.out if r.ok else "unknown"

    def usf_status_porcelain(self) -> str:
        r = _git(
            ["--no-optional-locks", "-C", str(self.usf_repo), "status", "--porcelain=v1", "-uall"]
        )
        return r.out if r.ok else ""

    def working_tree_digest(self) -> str:
        """Deterministic digest of HEAD + porcelain status (read-only)."""
        head = self.usf_head()
        status = self.usf_status_porcelain()
        # Sort status lines for determinism.
        status_sorted = "\n".join(sorted(status.splitlines()))
        return digest_text(f"{head}\n{status_sorted}")

    # ---- mirror --------------------------------------------------------- #

    def mirror_exists(self) -> bool:
        return (self.paths.mirror / "HEAD").exists() or (self.paths.mirror / "config").exists()

    def ensure_mirror(self) -> Path:
        """Create (or update) the factory-owned bare mirror from /usf."""
        mirror = self.paths.mirror
        before = self.assert_no_factory_worktrees()
        if not self.mirror_exists():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            if mirror.exists():
                shutil.rmtree(mirror)
            r = _git(
                [
                    "clone",
                    "--mirror",
                    "--no-hardlinks",
                    "--no-local",
                    str(self.usf_repo),
                    str(mirror),
                ],
                timeout=600.0,
            )
            if not r.ok:
                raise IsolationViolationError(f"mirror clone failed: {r.err}")
        else:
            self.fetch_mirror()
        after = self.assert_no_factory_worktrees()
        if set(after) - set(before):
            raise IsolationViolationError(
                f"mirror operation created /usf worktree(s): {set(after) - set(before)}"
            )
        return mirror

    def fetch_mirror(self) -> None:
        """Read-only fetch of updates from /usf into the mirror."""
        r = _git(["-C", str(self.paths.mirror), "fetch", "--prune", "origin"], timeout=600.0)
        if not r.ok and "origin" in r.err:
            # Some mirrors name the remote differently; try a direct fetch.
            _git(
                [
                    "-C",
                    str(self.paths.mirror),
                    "fetch",
                    "--prune",
                    str(self.usf_repo),
                    "+refs/*:refs/*",
                ],
                timeout=600.0,
            )

    def mirror_head(self, branch: str = "HEAD") -> str:
        r = _git(["-C", str(self.paths.mirror), "rev-parse", branch])
        return r.out if r.ok else ""

    # ---- disposable clones ---------------------------------------------- #

    def create_workspace(
        self,
        packet_id: str,
        run_id: str,
        base_head: str,
        sparse_paths: list[str] | None = None,
        *,
        checkout: bool = False,
    ) -> Path:
        """Create a disposable clone from the MIRROR (never from /usf).

        By default no working tree is checked out (fast, safe). ``sparse_paths``
        limits the checkout to the packet's relevant ranges.
        """
        dest = self.paths.workspaces / f"{packet_id}--{run_id}"
        self.assert_not_usf(dest)
        if dest.exists():
            shutil.rmtree(dest)
        r = _git(
            ["clone", "--no-checkout", "--no-hardlinks", str(self.paths.mirror), str(dest)],
            timeout=300.0,
        )
        if not r.ok:
            raise IsolationViolationError(f"workspace clone failed: {r.err}")
        # Remove any inherited remote so a worker cannot fetch/push externally.
        _git(["-C", str(dest), "remote", "remove", "origin"])
        if sparse_paths:
            _git(["-C", str(dest), "sparse-checkout", "init", "--cone"])
            _git(["-C", str(dest), "sparse-checkout", "set", *sparse_paths])
        if checkout or sparse_paths:
            co = _git(["-C", str(dest), "checkout", base_head], timeout=300.0)
            if not co.ok:
                # base_head may not be a branch name; try detached checkout
                _git(["-C", str(dest), "checkout", "--detach", base_head], timeout=300.0)
        return dest

    def integration_clone(self, set_id: str, base_head: str) -> Path:
        dest = self.paths.integration / set_id
        self.assert_not_usf(dest)
        if dest.exists():
            shutil.rmtree(dest)
        r = _git(
            ["clone", "--no-checkout", "--no-hardlinks", str(self.paths.mirror), str(dest)],
            timeout=300.0,
        )
        if not r.ok:
            raise IsolationViolationError(f"integration clone failed: {r.err}")
        _git(["-C", str(dest), "remote", "remove", "origin"])
        return dest

    def cleanup(self, path: Path) -> None:
        self.assert_not_usf(path)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
