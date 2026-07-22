"""Runtime context — the dependency-injection hub.

Ties together resolved paths, validated configuration, the durable store,
credential access, and redaction. Everything downstream takes a
:class:`RuntimeContext` rather than reaching for globals, which keeps the code
testable and the safety boundaries explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths as _paths
from . import secrets
from .clock import utc_now_iso
from .config import FactoryConfig, load_config
from .enums import ProtectedAction
from .errors import ProtectedActionError
from .event_store import Store, open_store
from .models import Event
from .paths import FactoryPaths, resolve_paths
from .run_authorization import RunAuthorization


@dataclass
class RuntimeContext:
    paths: FactoryPaths
    config: FactoryConfig
    store: Store
    env_file: Path
    usf_repo: Path = _paths.USF_REPO
    # Per-run operator grant. None ⇒ no protected action is effective this run.
    run_authorization: RunAuthorization | None = None

    # ---- credentials (names only unless writing) ------------------------ #

    def credential_present(self, reference: str | None) -> bool:
        """True if the credential referenced by ``env:NAME`` is present.

        Never returns or logs the value. ``cli:*`` and ``none`` are handled by
        their adapters (CLI auth / local), so they are reported as present here.
        """
        if not reference or reference == "none":
            return True
        if reference.startswith("cli:"):
            return True  # CLI adapters probe their own auth separately
        if reference.startswith("env:"):
            name = reference.split(":", 1)[1]
            allow = secrets.load_allowlisted_env(self.env_file)
            return name in allow and bool(allow[name].strip())
        return False

    def credential_value(self, reference: str) -> str | None:
        """Return the credential value for ``env:NAME`` (for adapter use only).

        The result must never be logged. Returns None for non-env references.
        """
        if not reference or not reference.startswith("env:"):
            return None
        name = reference.split(":", 1)[1]
        return secrets.load_allowlisted_env(self.env_file).get(name)

    # ---- protected-action gates ----------------------------------------- #

    def is_gate_enabled(self, action: ProtectedAction) -> bool:
        s = self.config.safety
        return {
            ProtectedAction.PAID_INFERENCE: s.allow_billable,
            ProtectedAction.SOURCE_EGRESS: s.allow_source_egress,
            ProtectedAction.MAIN_INTEGRATION: s.allow_main_integration,
            ProtectedAction.PUSH_PR: s.allow_push_pr,
            ProtectedAction.STARDOG_PUBLICATION: s.allow_stardog_publication,
            ProtectedAction.RISK_ACCEPTANCE: s.allow_risk_acceptance,
            ProtectedAction.TERMINAL_COMPLETION: s.allow_terminal_completion,
        }[action]

    def require_gate(self, action: ProtectedAction) -> None:
        if not self.is_gate_enabled(action):
            raise ProtectedActionError(
                f"protected action '{action.value}' is disabled by default; "
                f"enable it explicitly in config/safety.yaml"
            )

    # ---- per-run effective authorization -------------------------------- #

    def is_action_effective(self, action: ProtectedAction) -> bool:
        """True only when a live RunAuthorization explicitly permits ``action``.

        This is the per-run enabler required for any irreversible side effect
        (push/PR/merge/publish/terminal). Committed gates in ``config/safety.yaml``
        stay ``false`` by default; a protected action becomes effective for the
        current run only through an unexpired operator RunAuthorization that names
        it. The capability must also be built (the caller only reaches this check
        when the code path exists).
        """
        auth = self.run_authorization
        return auth is not None and auth.permits_action(action)

    def require_effective(self, action: ProtectedAction) -> None:
        if not self.is_action_effective(action):
            raise ProtectedActionError(
                f"protected action '{action.value}' is not authorised for this run "
                f"(no RunAuthorization permits it, or it has expired)"
            )

    # ---- events --------------------------------------------------------- #

    def log_event(
        self,
        kind: str,
        stage: str = "",
        cycle_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Append an event. Payload is redacted defensively before storage."""
        safe_payload = _redact_payload(payload or {})
        self.store.append_event(
            Event(cycle_id=cycle_id, kind=kind, stage=stage, payload=safe_payload, at=utc_now_iso())
        )

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> RuntimeContext:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub string values via the global redactor."""

    def scrub(v: Any) -> Any:
        if isinstance(v, str):
            return secrets.redact(v)
        if isinstance(v, dict):
            return {k: scrub(x) for k, x in v.items()}
        if isinstance(v, list):
            return [scrub(x) for x in v]
        return v

    return {k: scrub(v) for k, v in payload.items()}


def build_context(
    config_dir: Path | str | None = None,
    *,
    env_file: Path | str | None = None,
    usf_repo: Path | str | None = None,
) -> RuntimeContext:
    """Construct the runtime context: paths, config, store, redaction.

    ``env_file`` and ``usf_repo`` default to the canonical locations but may be
    overridden (used by tests to isolate from the real /root/.env and /usf).
    """
    paths = resolve_paths().ensure()
    config = load_config(config_dir)
    store = open_store(paths.db_path, paths.cas)
    resolved_env = Path(env_file) if env_file else _paths.ENV_FILE
    resolved_usf = Path(usf_repo) if usf_repo else _paths.USF_REPO
    # Load exact secret values into the global redactor so any accidental
    # inclusion in a log/report is scrubbed. Only allowlisted values are loaded.
    secrets.install_redaction_from_env(resolved_env)
    return RuntimeContext(
        paths=paths, config=config, store=store, env_file=resolved_env, usf_repo=resolved_usf
    )
