"""Operator RunAuthorization (build task — Operator-Authorised Scope).

The RunAuthorization is the operator-owned, mode-0600, expiring grant that bounds
a single live autonomous run. It is stored OUTSIDE both repositories and OUTSIDE
``/usf``. Its digest and exact scope are recorded in every protected-action
receipt so that any live side effect is provably bound to an explicit grant.

Safety model (enforced here and by the OS):

* Committed protected gates stay ``false`` by default (``config/safety.yaml``).
  A protected action becomes *effective for the current run* only when BOTH the
  committed capability exists AND this RunAuthorization explicitly permits it
  (:meth:`RunAuthorization.permits_action`).
* The file is validated fail-closed: it must be a regular file (no symlink),
  owned by the operator running the coordinator, and readable/writable by owner
  only (mode ``0600``/``0400``). AI models never run as that user and can never
  read, modify, or broaden it.
* An expired authorization permits nothing.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError, field_validator, model_validator

from .clock import utc_now_iso
from .enums import ProtectedAction, Risk
from .errors import RunAuthorizationError
from .models import FactoryModel


class RunAuthorization(FactoryModel):
    """A bounded, expiring operator grant for one live autonomous run."""

    schema_version: int = 1
    authorization_id: str
    issued_at: str
    expires_at: str

    # Scope
    repositories: list[str] = Field(default_factory=list)
    authority_database: str = ""
    permitted_risk: list[Risk] = Field(default_factory=lambda: [Risk.LOW, Risk.MEDIUM])
    prohibited_risk: list[Risk] = Field(default_factory=lambda: [Risk.HIGH, Risk.PROTECTED])

    # Provider routing / budget
    paid_api_budget_usd: float = Field(default=0.0, ge=0.0)
    allow_subscription_inference: bool = True
    raw_source_provider: str | None = None
    raw_source_requires_containment: bool = True
    metadata_review_provider: str | None = "codex-cli"

    # Quotas
    max_packets_per_wave: int = Field(default=2, ge=1)
    # Fail-closed migration defaults: an older authorization that lacks the new
    # fields gains no outward side-effect capacity.
    max_branch_pushes: int = Field(default=0, ge=0)
    max_pr_creations: int = Field(default=0, ge=0)
    max_authority_publications: int = Field(default=0, ge=0)
    max_pr_merges: int = Field(default=0, ge=0)
    max_continuous_cycles: int = Field(default=20, ge=1)
    # Which protected gates may become effective for this run.
    permitted_actions: list[ProtectedAction] = Field(default_factory=list)

    # Nothing here is volatile: the digest binds the exact, complete scope.
    _volatile_fields = frozenset()

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _strict_utc_timestamp(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("must be an exact UTC timestamp YYYY-MM-DDTHH:MM:SSZ") from exc
        return value

    @model_validator(mode="after")
    def _validate_scope(self) -> RunAuthorization:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        actions = set(self.permitted_actions)
        if (
            actions & {ProtectedAction.PUSH_PR, ProtectedAction.MAIN_INTEGRATION}
            and not self.repositories
        ):
            raise ValueError("Git protected actions require repository scope")
        if ProtectedAction.STARDOG_PUBLICATION in actions and not self.authority_database:
            raise ValueError("Stardog publication requires authority_database scope")
        return self

    # ---- runtime checks (fail closed) ----------------------------------- #

    def is_expired(self, now: str | None = None) -> bool:
        return (now or utc_now_iso()) >= self.expires_at

    def permits_action(self, action: ProtectedAction, now: str | None = None) -> bool:
        """True only if unexpired AND this action is explicitly permitted."""
        if self.is_expired(now):
            return False
        return action in self.permitted_actions

    def permits_risk(self, risk: Risk) -> bool:
        return risk in self.permitted_risk and risk not in self.prohibited_risk

    def covers_repository(self, repo: str) -> bool:
        return repo in self.repositories

    def paid_inference_allowed(self) -> bool:
        return self.paid_api_budget_usd > 0.0 and self.permits_action(
            ProtectedAction.PAID_INFERENCE
        )


def _assert_secure_file(path: Path) -> None:
    """Fail closed unless ``path`` is an operator-owned, 0600/0400 regular file."""
    if not path.exists():
        raise RunAuthorizationError(f"RunAuthorization file not found: {path}")
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise RunAuthorizationError(f"RunAuthorization must not be a symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise RunAuthorizationError(f"RunAuthorization must be a regular file: {path}")
    if st.st_mode & 0o077:
        raise RunAuthorizationError(
            f"RunAuthorization must be mode 0600/0400 (owner-only); got "
            f"{stat.S_IMODE(st.st_mode):#o}: {path}"
        )
    euid = os.geteuid()
    if st.st_uid != euid:
        raise RunAuthorizationError(
            f"RunAuthorization must be owned by the operator (uid {euid}); "
            f"owned by uid {st.st_uid}: {path}"
        )


def load_run_authorization(path: Path | str) -> RunAuthorization:
    """Load + validate a RunAuthorization, fail closed on any problem.

    Structural/security failures raise :class:`RunAuthorizationError`. Expiry is
    NOT raised here (an expired grant loads but permits nothing) so the caller can
    report it precisely.
    """
    p = Path(path)
    _assert_secure_file(p)
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RunAuthorizationError(f"RunAuthorization is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RunAuthorizationError("RunAuthorization must be a JSON object")
    try:
        return RunAuthorization.model_validate(data)
    except ValidationError as exc:
        raise RunAuthorizationError(f"RunAuthorization failed validation: {exc}") from exc


def write_run_authorization(auth: RunAuthorization, path: Path | str) -> str:
    """Write a RunAuthorization as an owner-only (0600) JSON file; return its digest.

    Only the operator/coordinator calls this. The file is created with a
    restrictive umask so it is never group/other-readable, and its parent must be
    outside both repositories (the caller chooses the path).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(auth.content_dict(), sort_keys=True, indent=2).encode("utf-8")
    temporary = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(temporary), flags, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    temporary.replace(p)
    p.chmod(0o600)
    return auth.digest()
