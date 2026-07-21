"""Filesystem locations for the factory.

All durable operational state lives OUTSIDE the repository and OUTSIDE /usf,
under XDG-style directories owned by root. These match the preferred paths in
DESIGN.md / the build task.

Locations may be overridden via environment variables (useful for tests), which
default to the canonical production paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# The live USF checkout. Read-only from the factory's perspective. We never
# write here and never register worktrees under its .git.
USF_REPO = Path(os.environ.get("USF_FACTORY_USF_REPO", "/usf"))

# The USF MCP STDIO server launch command (tools-only server). An empty
# resources list is expected and normal.
USF_MCP_COMMAND = os.environ.get(
    "USF_FACTORY_MCP_COMMAND",
    "set -a; [ -f /usf/.env ] && . /usf/.env; set +a; "
    "exec /usr/local/bin/node /usf/processes/semantic-assurance/semantic-authority-mcp.mjs",
)

# The secret file (root-owned, mode 0600). Never printed/committed/logged.
ENV_FILE = Path(os.environ.get("USF_FACTORY_ENV_FILE", "/root/.env"))


def _base(env_var: str, default: str) -> Path:
    return Path(os.environ.get(env_var, default)).expanduser()


@dataclass(frozen=True)
class FactoryPaths:
    """Resolved factory paths. Construct via :func:`resolve_paths`."""

    share: Path
    state: Path
    cache: Path
    config: Path

    @property
    def mirror(self) -> Path:
        """Factory-owned bare mirror of /usf (read-only fetch target)."""
        return self.share / "mirrors" / "usf.git"

    @property
    def workspaces(self) -> Path:
        """Root for disposable per-packet clones."""
        return self.share / "workspaces"

    @property
    def integration(self) -> Path:
        """Centralized integration clone root."""
        return self.share / "integration"

    @property
    def db_path(self) -> Path:
        """SQLite (WAL) state + event log."""
        return self.state / "factory.sqlite"

    @property
    def cas(self) -> Path:
        """Content-addressed artifact store (large catalogues, patches, logs)."""
        return self.cache / "cas"

    def ensure(self) -> FactoryPaths:
        """Create all directories if missing (idempotent)."""
        for d in (
            self.share,
            self.state,
            self.cache,
            self.config,
            self.share / "mirrors",
            self.workspaces,
            self.integration,
            self.cas,
        ):
            d.mkdir(parents=True, exist_ok=True)
        return self


def resolve_paths() -> FactoryPaths:
    """Resolve factory paths from the environment or canonical defaults."""
    return FactoryPaths(
        share=_base("USF_FACTORY_SHARE", "/root/.local/share/usf-factory"),
        state=_base("USF_FACTORY_STATE", "/root/.local/state/usf-factory"),
        cache=_base("USF_FACTORY_CACHE", "/root/.cache/usf-factory"),
        config=_base("USF_FACTORY_CONFIG", "/root/.config/usf-factory"),
    )


def repo_root() -> Path:
    """Best-effort path to this repository root (for bundled config/schemas)."""
    # src/usf_factory/paths.py -> repo root is three parents up.
    return Path(__file__).resolve().parents[2]


def bundled_config_dir() -> Path:
    return repo_root() / "config"


def bundled_schema_dir() -> Path:
    return repo_root() / "schemas"


def bundled_qualifications_dir() -> Path:
    return repo_root() / "qualifications"
