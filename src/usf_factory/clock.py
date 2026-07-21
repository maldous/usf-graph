"""Time source.

Wall-clock time is metadata only. It never participates in the *identity*
(content address) of a durable artifact, so replays remain deterministic. Tests
may install a fixed clock via :func:`set_clock`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime


def _default_clock() -> datetime:
    return datetime.now(UTC)


_clock: Callable[[], datetime] = _default_clock


def set_clock(fn: Callable[[], datetime]) -> None:
    """Override the clock (for deterministic tests)."""
    global _clock
    _clock = fn


def reset_clock() -> None:
    global _clock
    _clock = _default_clock


def utc_now() -> datetime:
    return _clock()


def utc_now_iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
