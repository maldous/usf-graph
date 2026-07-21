"""Sortable unique identifiers (ULID).

Cycle ids must be unique under concurrent schedulers and lexicographically
sortable by creation time (so "latest cycle" is well-defined). A ULID gives both
without a database round-trip. Randomness/time here are for *uniqueness*, not for
content identity — content addressing still uses deterministic digests.
"""

from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def ulid() -> str:
    """A 26-character Crockford-base32 ULID (48-bit ms time + 80-bit random)."""
    ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")  # 80 bits
    return _encode(ms, 10) + _encode(rand, 16)


def cycle_id() -> str:
    return "cyc-" + ulid()


def run_id(cycle: str, packet_id: str) -> str:
    """A run id unique per (cycle, packet, attempt)."""
    return f"{cycle}-{packet_id[-8:]}-{ulid()[-8:]}"
