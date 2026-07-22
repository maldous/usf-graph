"""Deterministic canonicalization and content addressing.

Every durable artifact in the factory is content-addressed by a SHA-256 over its
*canonical JSON* form. Canonical form is:

* UTF-8 encoded,
* object keys sorted lexicographically,
* no insignificant whitespace,
* ``NaN``/``Infinity`` rejected (not valid JSON),
* stable across processes and platforms.

No wall-clock, locale, or randomness participates in identity. This is the
foundation of replayability: identical inputs always yield identical digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_DIGEST_PREFIX = "sha256:"
_RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TAGGED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    """Return the canonical JSON string for ``value``.

    Uses sorted keys, compact separators, and ``ensure_ascii=False`` so that
    identical semantic content produces identical bytes regardless of insertion
    order. ``allow_nan=False`` guarantees valid, portable JSON.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON encoded as UTF-8 bytes."""
    return canonical_json(value).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    """SHA-256 of raw bytes, prefixed with ``sha256:``."""
    return _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def digest_text(text: str) -> str:
    """SHA-256 of a text string (UTF-8), prefixed with ``sha256:``."""
    return digest_bytes(text.encode("utf-8"))


def canonical_authority_digest(value: str) -> str:
    """Canonicalise equivalent USF MCP SHA-256 witness representations.

    ``usf_bootstrap`` carries the algorithm separately and can expose only the
    64 hexadecimal digest, while gateway projections expose ``sha256:<hex>``.
    Only that exact, lossless representation difference is normalised; other
    identifiers remain unchanged for their caller's fail-closed validation.
    """
    candidate = value.strip()
    if _RAW_SHA256_RE.fullmatch(candidate):
        return f"{_DIGEST_PREFIX}{candidate}"
    if _TAGGED_SHA256_RE.fullmatch(candidate):
        return candidate
    return candidate


def require_sha256_digest(value: str, field: str = "digest") -> str:
    """Return the one canonical SHA-256 form or fail closed."""
    candidate = canonical_authority_digest(value)
    if not _TAGGED_SHA256_RE.fullmatch(candidate):
        raise ValueError(f"{field} must be an exact SHA-256 digest")
    return candidate


def content_digest(value: Any) -> str:
    """Content address of any JSON-serializable value.

    This is the canonical identity function used for snapshots, packets,
    catalogues, patches (as metadata), and every other durable record.
    """
    return digest_bytes(canonical_bytes(value))


def short_digest(digest: str, length: int = 12) -> str:
    """A short, human-friendly form of a ``sha256:`` digest for display only.

    Never use the short form for identity or lookups.
    """
    body = digest.split(":", 1)[-1]
    return body[:length]


def stable_id(prefix: str, value: Any, length: int = 16) -> str:
    """A deterministic, human-readable identifier derived from content.

    Example: ``stable_id("pkt", packet_body)`` -> ``pkt-1a2b3c...``.
    """
    body = content_digest(value).split(":", 1)[-1]
    return f"{prefix}-{body[:length]}"
