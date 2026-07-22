"""OS-enforced worker sandbox (build task §14 / review P0-6).

Enforcement is done by the operating system, not by trusting the model:

* **Privilege drop** — commands run as an unprivileged uid (``nobody`` by
  default). Because ``/root/.env`` is mode 0600 (root) and ``/usf`` is
  root-owned, the dropped process is *physically* denied reading secrets or
  writing ``/usf`` — verified in the adversarial escape suite.
* **Resource limits** — ``RLIMIT_CPU``, ``RLIMIT_AS`` (memory), ``RLIMIT_FSIZE``
  and ``RLIMIT_NPROC`` via a ``preexec_fn``.
* **No new privileges** — ``PR_SET_NO_NEW_PRIVS``.
* **Process-group timeout** — the whole group is killed on timeout.
* **Sanitized environment** — no credentials are ever passed in.

Honest limitation of THIS environment: user namespaces are blocked and
``bwrap``/``unshare`` cannot create mount/network namespaces here, so
filesystem confinement of *world-readable* files and per-process network
isolation are **not** enforced. Those require namespaces (declared in
:meth:`capabilities`). Mutation stays disabled partly for this reason. When a
namespace tool becomes available it is used automatically (see
``_namespace_wrapper``).
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import pwd
import resource
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_PR_SET_NO_NEW_PRIVS = 38

# Only these environment keys are ever forwarded (never a credential).
_SAFE_ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR")


@dataclass
class SandboxLimits:
    cpu_seconds: int = 120
    memory_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    file_size_bytes: int = 256 * 1024 * 1024  # 256 MiB
    max_processes: int = 256


@dataclass
class SandboxResult:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class SandboxRunner:
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    drop_to_user: str = "nobody"
    _namespace_usable: bool | None = field(default=None, init=False, repr=False)

    # ---- capability reporting (honest) ---------------------------------- #

    def _resolve_uid(self) -> tuple[int, int] | None:
        """The (uid, gid) to drop to, or None if we cannot drop privileges."""
        if os.geteuid() != 0:
            return None  # not root -> cannot change uid
        try:
            pw = pwd.getpwnam(self.drop_to_user)
        except KeyError:
            return None
        return (pw.pw_uid, pw.pw_gid)

    def capabilities(self) -> dict[str, bool]:
        drop = self._resolve_uid() is not None
        ns = self._namespace_available()
        return {
            "privilege_drop": drop,  # protects 0600 secrets + root-owned /usf
            "rlimits": True,  # CPU/memory/file-size/nproc
            "no_new_privs": True,
            "process_group_timeout": True,
            "sanitized_env": True,
            "filesystem_namespace": ns,  # not available in this chroot
            "network_namespace": ns,  # not available in this chroot
        }

    def _namespace_available(self) -> bool:
        """Return true only when the exact namespace wrapper can execute.

        Package presence is not a capability: chroots, container policies and
        seccomp can leave ``bwrap`` installed while denying namespace creation.
        Probe under the same identity and limits used for an actual command so
        an unusable binary cannot turn otherwise safe execution into failure.
        """
        if self._namespace_usable is not None:
            return self._namespace_usable
        executable = shutil.which("bwrap")
        if executable is None:
            self._namespace_usable = False
            return False
        probe = [
            executable,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/usr/bin/true",
        ]
        try:
            completed = subprocess.run(
                probe,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                check=False,
                preexec_fn=self._preexec(self._resolve_uid()),
            )
            self._namespace_usable = completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            self._namespace_usable = False
        return self._namespace_usable

    # ---- execution ------------------------------------------------------- #

    def _preexec(self, uid_gid: tuple[int, int] | None):
        limits = self.limits

        def _fn() -> None:  # runs in the child after fork, before exec
            os.setsid()  # new process group for group-kill
            # No new privileges.
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            except OSError:
                pass
            # Resource limits.
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (limits.file_size_bytes, limits.file_size_bytes)
            )
            with contextlib.suppress(ValueError, OSError):
                resource.setrlimit(
                    resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes)
                )
            # Drop privileges LAST (after which we cannot change limits/uid again).
            if uid_gid is not None:
                uid, gid = uid_gid
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)

        return _fn

    def prepare_workspace(self, path: str) -> None:
        """Give the sandbox user ownership of its workspace so it can write there
        (only meaningful when privilege drop is active)."""
        uid_gid = self._resolve_uid()
        if uid_gid is None:
            return
        uid, gid = uid_gid
        for root, dirs, files in os.walk(path):
            os.chown(root, uid, gid)
            for name in dirs + files:
                with contextlib.suppress(OSError):
                    os.chown(str(Path(root) / name), uid, gid)

    def _namespace_wrapper(self, argv: list[str]) -> list[str]:
        """Prefix argv with a namespace sandbox if one is available (none in this
        environment). Kept so isolation upgrades automatically when present."""
        if self._namespace_available():
            return [
                str(shutil.which("bwrap")),
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/bin",
                "/bin",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--",
                *argv,
            ]
        return argv

    def run(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        timeout_s: float = 120.0,
        stdin: str | None = None,
    ) -> SandboxResult:
        env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        uid_gid = self._resolve_uid()
        full_argv = self._namespace_wrapper(argv)
        proc = subprocess.Popen(
            full_argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=self._preexec(uid_gid),
        )
        try:
            out, err = proc.communicate(stdin, timeout=timeout_s)
            return SandboxResult(rc=proc.returncode, stdout=out, stderr=err)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            out, err = proc.communicate()
            return SandboxResult(rc=124, stdout=out, stderr=err, timed_out=True)
