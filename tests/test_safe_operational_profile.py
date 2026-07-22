from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import yaml

from usf_factory.engine import FactoryEngine
from usf_factory.enums import AuthMode
from usf_factory.runtime import _policy_allows_profile, select_plan_optimizer
from usf_factory.workforce_policy import effective_policy

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run-safe-adaptive.sh"
SUPERVISOR = ROOT / "supervisor" / "usf-factory-safe.conf"


def _authorization(tmp_path: Path, **overrides: object) -> Path:
    body: dict[str, object] = {
        "schema_version": 1,
        "authorization_id": "safe-test",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "repositories": [],
        "authority_database": "USF",
        "permitted_risk": ["low", "medium"],
        "prohibited_risk": ["high", "protected"],
        "paid_api_budget_usd": 0.0,
        "allow_subscription_inference": True,
        "raw_source_provider": None,
        "raw_source_requires_containment": True,
        "metadata_review_provider": "codex-cli",
        "max_packets_per_wave": 3,
        "max_branch_pushes": 0,
        "max_pr_creations": 0,
        "max_authority_publications": 0,
        "max_pr_merges": 0,
        "max_continuous_cycles": 2,
        "permitted_actions": [],
    }
    body.update(overrides)
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    path.chmod(0o600)
    return path


def _run_launcher(tmp_path: Path, authorization: Path) -> subprocess.CompletedProcess[str]:
    credential = tmp_path / "empty.env"
    credential.write_text("", encoding="utf-8")
    credential.chmod(0o600)
    executable = tmp_path / ".venv" / "bin" / "usf-factory"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    executable.chmod(0o755)
    env = {
        "PATH": os.environ["PATH"],
        "USF_FACTORY_SAFE_AUTHORIZATION": str(authorization),
        "USF_FACTORY_ENV_FILE": str(credential),
        "USF_FACTORY_SAFE_WORKFORCE_POLICY": str(ROOT / "config" / "safe-adaptive-execution.yaml"),
    }
    text = LAUNCHER.read_text(encoding="utf-8").replace(
        "repo=/root/usf-factory", f"repo={tmp_path!s}"
    )
    copied = tmp_path / "launcher.sh"
    copied.write_text(text, encoding="utf-8")
    copied.chmod(0o700)
    return subprocess.run([str(copied)], env=env, text=True, capture_output=True, check=False)


def test_safe_workforce_policy_is_subscription_only() -> None:
    policy = yaml.safe_load(
        (ROOT / "config" / "safe-adaptive-execution.yaml").read_text(encoding="utf-8")
    )
    assert policy["only_providers"] == ["claude-cli"]
    assert policy["only_models"] == ["claude-opus-4-8"]
    assert policy["only_inference_modes"] == ["subscription"]
    assert policy["allow_subscription"] is True
    assert policy["allow_local"] is False
    assert policy["allow_free"] is False
    assert policy["allow_paid"] is False
    assert policy["max_paid_cost_usd"] == 0.0
    assert policy["enable_plan_optimizer"] is False


def test_safe_policy_governs_every_runtime_ai_selection(ctx) -> None:
    policy = effective_policy(
        config_dir=ROOT / "config",
        operator_policy_path=ROOT / "config" / "safe-adaptive-execution.yaml",
    )
    claude = SimpleNamespace(
        provider_id="claude-cli",
        requested_model_id="claude-opus-4-8",
        adapter="claude_cli",
        auth_mode=AuthMode.OIDC_CLI,
    )
    codex = SimpleNamespace(
        provider_id="codex-cli",
        requested_model_id="gpt-5-codex",
        adapter="codex_cli",
        auth_mode=AuthMode.OIDC_CLI,
    )
    assert _policy_allows_profile(policy, claude)
    assert not _policy_allows_profile(policy, codex)
    assert select_plan_optimizer(ctx, allow_billable=True, policy=policy) == (None, None)


def test_subscription_equivalent_cost_never_consumes_paid_api_budget(ctx) -> None:
    committed: list[float] = []

    class Ledger:
        def commit(self, **kwargs):
            committed.append(float(kwargs["actual_usd"]))
            return True, "settled"

    agent = SimpleNamespace(provider_id="claude-cli", auth_mode=AuthMode.OIDC_CLI)
    result = SimpleNamespace(usage={"provider_reported_cost": 12.5})
    FactoryEngine(ctx)._settle_budget(Ledger(), "cycle", agent, None, 0.0, result, "reservation")
    assert committed == [0.0]


def test_safe_launcher_uses_authorized_work_volume_not_concurrency(tmp_path: Path) -> None:
    result = _run_launcher(tmp_path, _authorization(tmp_path))
    assert result.returncode == 0, result.stderr
    args = result.stdout.splitlines()
    assert "shadow" in args
    assert "--allow-subscription-inference" in args
    assert args[args.index("--max-packets-per-wave") + 1] == "3"
    assert args[args.index("--max-cycles") + 1] == "2"
    assert not any("concurr" in arg for arg in args)


def test_safe_launcher_rejects_any_protected_action(tmp_path: Path) -> None:
    result = _run_launcher(tmp_path, _authorization(tmp_path, permitted_actions=["push_pr"]))
    assert result.returncode == 2
    assert "exceeds SAFE_ADAPTIVE_EXECUTION envelope" in result.stderr


def test_safe_launcher_rejects_any_outward_quota(tmp_path: Path) -> None:
    result = _run_launcher(tmp_path, _authorization(tmp_path, max_pr_creations=1))
    assert result.returncode == 2
    assert "exceeds SAFE_ADAPTIVE_EXECUTION envelope" in result.stderr


def test_supervisor_starts_from_empty_environment_and_rotates_logs() -> None:
    text = SUPERVISOR.read_text(encoding="utf-8")
    assert "command=/usr/bin/env -i " in text
    assert "autorestart=unexpected" in text
    assert "stopasgroup=true" in text
    assert "killasgroup=true" in text
    assert "stdout_logfile_maxbytes=" in text
    assert "stdout_logfile_backups=" in text
    for forbidden in ("API_KEY", "GITHUB_PERSONAL_ACCESS_TOKEN", "STARDOG_PASSWORD"):
        assert forbidden not in text
