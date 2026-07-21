"""Exception hierarchy for the factory.

Errors are typed so the control plane can classify failures deterministically
and attribute them to the correct stage (see ``failure_taxonomy``).
"""

from __future__ import annotations


class FactoryError(Exception):
    """Base class for all factory errors."""


class ConfigError(FactoryError):
    """Configuration is missing, malformed, or internally inconsistent."""


class CredentialError(FactoryError):
    """A credential problem detected without ever exposing a value."""


class CredentialConflictError(CredentialError):
    """Two non-empty aliases for the same canonical variable disagree."""


class IsolationViolationError(FactoryError):
    """An operation would breach isolation from /usf or a sandbox boundary."""


class AuthorityError(FactoryError):
    """A problem talking to the USF MCP authority boundary."""


class AuthorityConflictError(AuthorityError):
    """Authority state is internally inconsistent or drifted; fail closed."""


class SnapshotError(FactoryError):
    """The deterministic semantic snapshot could not be compiled."""


class PlanningError(FactoryError):
    """The planner or critic produced an invalid obligation graph."""


class PacketCompilationError(FactoryError):
    """A packet set could not be compiled deterministically."""


class SchedulingError(FactoryError):
    """No eligible agent could be selected under hard constraints."""


class WorkerError(FactoryError):
    """A worker adapter failed to execute or returned an invalid result."""


class ResultValidationError(FactoryError):
    """A packet result failed deterministic qualification."""


class IntegrationError(FactoryError):
    """Deterministic or AI integration could not produce a valid wave patch."""


class ProtectedActionError(FactoryError):
    """A protected action was attempted while its gate is disabled."""


class BudgetExceededError(FactoryError):
    """An action would exceed a configured budget."""


class StaleSnapshotError(FactoryError):
    """Work references a snapshot/commit that is no longer current."""
