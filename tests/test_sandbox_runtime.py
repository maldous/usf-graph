"""P0-6: adversarial escape suite against the OS-enforced sandbox.

These tests assert the OPERATING SYSTEM blocks the escape, not a prompt string.
The privilege-drop protections require running as root (they are skipped
otherwise, with the reason recorded).
"""

from __future__ import annotations

import os
import shutil

import pytest

from usf_factory.sandbox_runtime import SandboxLimits, SandboxRunner

IS_ROOT = os.geteuid() == 0
root_only = pytest.mark.skipif(not IS_ROOT, reason="privilege-drop requires root")

# Use a SYSTEM python the dropped (nobody) user can actually execute — the venv
# interpreter lives under /root (mode 0700) and is not traversable once dropped.
PY = shutil.which("python3", path="/usr/bin:/bin") or "/usr/bin/python3"


@pytest.mark.adversarial
def test_capabilities_are_reported_honestly():
    caps = SandboxRunner().capabilities()
    assert caps["rlimits"] and caps["no_new_privs"] and caps["sanitized_env"]
    assert caps["process_group_timeout"]
    # In this environment namespaces are unavailable; must be reported as such.
    assert caps["privilege_drop"] == IS_ROOT


@pytest.mark.adversarial
@root_only
def test_cannot_read_root_env():
    r = SandboxRunner().run([PY, "-c", "open('/root/.env').read()"])
    assert r.rc != 0  # PermissionError under the dropped uid


@pytest.mark.adversarial
@root_only
def test_cannot_write_usf():
    r = SandboxRunner().run([PY, "-c", "open('/usf/factory_escape_probe','w').write('x')"])
    assert r.rc != 0
    assert not os.path.exists("/usf/factory_escape_probe")


@pytest.mark.adversarial
@root_only
def test_cannot_write_root_home():
    r = SandboxRunner().run([PY, "-c", "open('/root/escape_probe','w').write('x')"])
    assert r.rc != 0
    assert not os.path.exists("/root/escape_probe")


@pytest.mark.adversarial
def test_sanitized_env_has_no_secrets():
    # Even a benign command sees no provider credentials in its environment.
    r = SandboxRunner().run([PY, "-c", "import os,json;print(json.dumps(sorted(os.environ)))"])
    assert r.rc == 0
    for leaky in (
        "OPENAI_API_KEY",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "STARDOG_TOKEN",
        "ANTHROPIC_API_KEY",
    ):
        assert leaky not in r.stdout


@pytest.mark.adversarial
def test_process_group_timeout_kills_runaway():
    r = SandboxRunner().run([PY, "-c", "import time\nwhile True: time.sleep(1)"], timeout_s=1.0)
    assert r.timed_out and r.rc == 124


@pytest.mark.adversarial
def test_file_size_limit_enforced():
    # RLIMIT_FSIZE should stop an attempt to write a huge file.
    limits = SandboxLimits(file_size_bytes=1024)
    r = SandboxRunner(limits=limits).run(
        [PY, "-c", "open('big','wb').write(b'x'*10_000_000)"],
        cwd="/tmp",
        timeout_s=30,
    )
    assert r.rc != 0  # killed by SIGXFSZ or write error
