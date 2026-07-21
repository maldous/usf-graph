"""Durable state: SQLite (WAL) + content-addressed artifact store.

The event log is append-only and is the source of truth for replay. Typed
records are stored in named tables (the durable artifacts of DESIGN §4 / build
task §9). Large raw blobs (catalogues, patches, prompts, logs) live in a
content-addressed store on disk and are referenced by digest.

No credential value is ever stored here — callers must redact before persisting.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_json, digest_bytes
from .clock import utc_now_iso
from .models import Event

# --------------------------------------------------------------------------- #
# Schema. Each record table follows a uniform shape: a primary/natural id, an
# optional content digest, the canonical JSON payload, indexed query columns,
# and a timestamp. Append-only tables use an autoincrement `seq`.
# --------------------------------------------------------------------------- #

_RECORD_TABLES: dict[str, list[str]] = {
    # table: list of extra indexed columns (besides id/payload/created_at)
    "providers": [],
    "provider_catalogues": ["provider_id", "expires_at"],
    "models": ["provider_id"],
    "agent_profiles": [],
    "qualification_suites": [],
    "qualification_runs": ["agent_profile_id", "expires_at"],
    "task_classes": [],
    "model_task_scores": ["agent_profile_id", "task_class", "dimension"],
    "semantic_snapshots": ["authority_digest", "repository_head"],
    "obligation_graphs": ["snapshot_id"],
    "packet_sets": ["snapshot_id", "graph_id"],
    "packets": ["set_id", "task_class"],
    "agent_runs": ["packet_id", "agent_profile_id"],
    "packet_results": ["packet_id", "status"],
    "integration_attempts": ["set_id"],
    "wave_patches": ["set_id"],
    "wave_reviews": ["set_id"],
    "validation_receipts": ["set_id"],
    "publication_receipts": ["set_id"],
    "routing_decisions": ["packet_id"],
    "cycles": ["state"],
}

_APPEND_TABLES: dict[str, list[str]] = {
    "events": ["cycle_id", "kind", "stage"],
    "provider_health_events": ["provider_id", "status"],
    "quota_events": ["provider_id"],
}


class Store:
    """The durable state store. Not thread-safe; use one per process/loop."""

    def __init__(self, db_path: Path, cas_dir: Path) -> None:
        self.db_path = db_path
        self.cas_dir = cas_dir
        db_path.parent.mkdir(parents=True, exist_ok=True)
        cas_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=OFF")
        self._create_schema()

    # ---- lifecycle ------------------------------------------------------- #

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # ---- schema ---------------------------------------------------------- #

    def _create_schema(self) -> None:
        cur = self._conn
        for table, extra in _RECORD_TABLES.items():
            cols = ["id TEXT PRIMARY KEY", "digest TEXT", "payload TEXT NOT NULL"]
            cols += [f"{c} TEXT" for c in extra]
            cols += ["created_at TEXT NOT NULL"]
            cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)})")
            for c in extra:
                cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_{c} ON {table}({c})")
        for table, extra in _APPEND_TABLES.items():
            cols = ["seq INTEGER PRIMARY KEY AUTOINCREMENT", "payload TEXT NOT NULL"]
            cols += [f"{c} TEXT" for c in extra]
            cols += ["at TEXT NOT NULL"]
            cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)})")
            for c in extra:
                cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_{c} ON {table}({c})")
        # Lease / claim authority: exactly one active claim per packet.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS packet_claims (
                packet_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL,           -- active | released | expired
                claimed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (packet_id, run_id)
            )
            """
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_packet_active_claim "
            "ON packet_claims(packet_id) WHERE status = 'active'"
        )

    # ---- generic record ops ---------------------------------------------- #

    def put(
        self,
        table: str,
        id_: str,
        payload: dict[str, Any],
        *,
        digest: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if table not in _RECORD_TABLES:
            raise KeyError(f"unknown record table: {table}")
        extra = extra or {}
        for c in extra:
            if c not in _RECORD_TABLES[table]:
                raise KeyError(f"column {c} not indexed on {table}")
        cols = ["id", "digest", "payload", *extra.keys(), "created_at"]
        vals = [id_, digest, canonical_json(payload), *extra.values(), utc_now_iso()]
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        self._conn.execute(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}",
            vals,
        )

    def get(self, table: str, id_: str) -> dict[str, Any] | None:
        row = self._conn.execute(f"SELECT payload FROM {table} WHERE id = ?", (id_,)).fetchone()
        if row is None:
            return None
        return _loads(row["payload"])

    def exists(self, table: str, id_: str) -> bool:
        row = self._conn.execute(f"SELECT 1 FROM {table} WHERE id = ? LIMIT 1", (id_,)).fetchone()
        return row is not None

    def records(
        self, table: str, where: str | None = None, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]:
        sql = f"SELECT payload FROM {table}"
        if where:
            sql += f" WHERE {where}"
        rows = self._conn.execute(sql, params).fetchall()
        return [_loads(r["payload"]) for r in rows]

    def items(
        self, table: str, where: str | None = None, params: tuple[Any, ...] = ()
    ) -> list[tuple[str, dict[str, Any]]]:
        """Return (id, payload) pairs — useful when the payload omits its own id
        (ids are computed properties, persisted as the row primary key)."""
        sql = f"SELECT id, payload FROM {table}"
        if where:
            sql += f" WHERE {where}"
        rows = self._conn.execute(sql, params).fetchall()
        return [(r["id"], _loads(r["payload"])) for r in rows]

    def count(self, table: str, where: str | None = None, params: tuple[Any, ...] = ()) -> int:
        sql = f"SELECT COUNT(*) AS n FROM {table}"
        if where:
            sql += f" WHERE {where}"
        row = self._conn.execute(sql, params).fetchone()
        return int(row["n"])

    # ---- append-only logs ------------------------------------------------ #

    def append(
        self, table: str, payload: dict[str, Any], extra: dict[str, Any] | None = None
    ) -> int:
        if table not in _APPEND_TABLES:
            raise KeyError(f"unknown append table: {table}")
        extra = extra or {}
        cols = ["payload", *extra.keys(), "at"]
        vals = [canonical_json(payload), *extra.values(), utc_now_iso()]
        placeholders = ",".join("?" for _ in cols)
        cur = self._conn.execute(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})", vals
        )
        return int(cur.lastrowid or 0)

    def append_event(self, event: Event) -> int:
        payload = event.model_dump(mode="json")
        return self.append(
            "events",
            payload,
            extra={"cycle_id": event.cycle_id, "kind": event.kind, "stage": event.stage},
        )

    def events(self, cycle_id: str | None = None) -> list[dict[str, Any]]:
        if cycle_id is None:
            rows = self._conn.execute("SELECT payload FROM events ORDER BY seq").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT payload FROM events WHERE cycle_id = ? ORDER BY seq", (cycle_id,)
            ).fetchall()
        return [_loads(r["payload"]) for r in rows]

    # ---- claim / lease authority ---------------------------------------- #

    def claim_packet(self, packet_id: str, run_id: str, owner: str, expires_at: str) -> bool:
        """Attempt to claim a packet. Returns True iff this call won the claim.

        The partial unique index guarantees at most one active claim per packet,
        so a duplicate claim from a retry/crash cannot double-dispatch.
        """
        try:
            self._conn.execute(
                "INSERT INTO packet_claims (packet_id, run_id, owner, status, claimed_at, expires_at) "
                "VALUES (?, ?, ?, 'active', ?, ?)",
                (packet_id, run_id, owner, utc_now_iso(), expires_at),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def release_packet(self, packet_id: str, run_id: str) -> None:
        self._conn.execute(
            "UPDATE packet_claims SET status='released' WHERE packet_id=? AND run_id=?",
            (packet_id, run_id),
        )

    def active_claim(self, packet_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM packet_claims WHERE packet_id=? AND status='active'",
            (packet_id,),
        ).fetchone()
        return dict(row) if row else None

    # ---- content-addressed store ---------------------------------------- #

    def cas_put(self, data: bytes) -> str:
        """Store bytes; returns a ``cas:sha256:...`` reference."""
        dg = digest_bytes(data)  # sha256:hex
        hexpart = dg.split(":", 1)[1]
        shard = self.cas_dir / hexpart[:2] / hexpart[2:4]
        shard.mkdir(parents=True, exist_ok=True)
        target = shard / hexpart
        if not target.exists():
            tmp = target.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(target)
        return f"cas:{dg}"

    def cas_put_text(self, text: str) -> str:
        return self.cas_put(text.encode("utf-8"))

    def cas_get(self, ref: str) -> bytes:
        if not ref.startswith("cas:sha256:"):
            raise ValueError(f"invalid CAS ref: {ref}")
        hexpart = ref.split("sha256:", 1)[1]
        target = self.cas_dir / hexpart[:2] / hexpart[2:4] / hexpart
        return target.read_bytes()

    def cas_has(self, ref: str) -> bool:
        try:
            hexpart = ref.split("sha256:", 1)[1]
        except IndexError:
            return False
        return (self.cas_dir / hexpart[:2] / hexpart[2:4] / hexpart).exists()


def _loads(payload: str) -> dict[str, Any]:
    import json

    return json.loads(payload)


def open_store(db_path: Path, cas_dir: Path) -> Store:
    return Store(db_path, cas_dir)
