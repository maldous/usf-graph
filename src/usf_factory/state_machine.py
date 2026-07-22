"""Cycle state machine (DESIGN Phase 0 / build task §22).

The deterministic control plane owns state. Transitions are validated and every
transition is persisted (before and after side effects) via the event log, which
is the basis of replay and recovery.
"""

from __future__ import annotations

from collections.abc import Callable

from .enums import CycleState
from .errors import FactoryError

# Allowed transitions. Terminal states have no outgoing edges except to FAILED.
_TRANSITIONS: dict[CycleState, set[CycleState]] = {
    CycleState.INIT: {CycleState.READY, CycleState.BLOCKED, CycleState.FAILED},
    CycleState.READY: {
        CycleState.SNAPSHOT,
        CycleState.BLOCKED,
        CycleState.PAUSED,
        CycleState.FAILED,
    },
    CycleState.SNAPSHOT: {CycleState.PLANNED, CycleState.BLOCKED, CycleState.FAILED},
    CycleState.PLANNED: {CycleState.COMPILED, CycleState.BLOCKED, CycleState.FAILED},
    CycleState.COMPILED: {
        CycleState.SCHEDULED,
        CycleState.NO_PROGRESS,
        CycleState.LEARNED,
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.SCHEDULED: {
        CycleState.EXECUTING,
        CycleState.LEARNED,  # plan-only / observe stop here
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.EXECUTING: {CycleState.INTEGRATING, CycleState.BLOCKED, CycleState.FAILED},
    # Validate BEFORE review so the reviewer receives the actual validation
    # evidence; both orderings are permitted.
    CycleState.INTEGRATING: {
        CycleState.VALIDATING,
        CycleState.REVIEWING,
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.VALIDATING: {
        CycleState.REVIEWING,
        CycleState.LEARNED,
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.REVIEWING: {
        CycleState.VALIDATING,
        CycleState.LEARNED,
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.LEARNED: {
        CycleState.COMPLETE,
        CycleState.READY,
        CycleState.NO_PROGRESS,
        CycleState.BLOCKED,
        CycleState.FAILED,
    },
    CycleState.PAUSED: {CycleState.READY, CycleState.FAILED},
    CycleState.NO_PROGRESS: {CycleState.READY, CycleState.BLOCKED, CycleState.FAILED},
    CycleState.BLOCKED: {CycleState.READY, CycleState.FAILED},
    CycleState.COMPLETE: set(),
    CycleState.FAILED: set(),
}


class CycleStateMachine:
    def __init__(
        self,
        state: CycleState = CycleState.INIT,
        on_transition: Callable[[CycleState], None] | None = None,
    ) -> None:
        self.state = state
        self.history: list[CycleState] = [state]
        self._on_transition = on_transition

    def can(self, to: CycleState) -> bool:
        return to in _TRANSITIONS.get(self.state, set())

    def transition(self, to: CycleState) -> CycleState:
        if not self.can(to):
            raise FactoryError(f"invalid cycle transition {self.state.value} -> {to.value}")
        self.state = to
        self.history.append(to)
        if self._on_transition is not None:
            self._on_transition(to)
        return to

    @property
    def is_terminal(self) -> bool:
        return self.state in (CycleState.COMPLETE, CycleState.FAILED)
