"""Durable state: SQLite (WAL) + content-addressed artifact store.

The event log is append-only and is the source of truth for replay. Typed
records are stored in named tables (the durable artifacts of DESIGN §4 / build
task §9). Large raw blobs (catalogues, patches, prompts, logs) live in a
content-addressed store on disk and are referenced by digest.

No credential value is ever stored here — callers must redact before persisting.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
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
    # Immutable probe runs (keyed by run_id) and admission decisions.
    "probe_runs": ["agent_profile_id"],
    "admission_decisions": ["agent_profile_id", "qualification_run_id"],
    # Append-only, digest-bound ownership evidence (subject -> owner path).
    "ownership_evidence": ["subject", "owner_path", "verified"],
    # One coverage row per provider per evaluation run; the active role roster.
    "provider_evaluations": ["provider_id", "eval_suite_version"],
    "role_rosters": [],
    # Dynamic evidence-based workforce snapshot (bounded cache of eligible
    # profiles; TTL + digest staleness) — replaces the fixed-primary roster.
    "workforce_snapshots": ["policy_digest", "config_digest"],
    # Demonstrated (observed) adapter capabilities, e.g. bounded_patch_synthesis
    # proven by a real git-derived patch; and per-profile runtime metrics.
    "capability_observations": ["provider_id", "capability"],
    "profile_metrics": ["agent_profile_id", "task_class"],
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
    # Full replayable dynamic-dispatch outcome per packet run: the ordered attempts
    # (with actual provider/model + fallback), and the final selection.
    "dispatch_outcomes": ["packet_id"],
    # Durable, idempotent delivery-lifecycle records (one per obligation delivery).
    "delivery_records": ["obligation_id", "state"],
    # Authorization-bound reservations/consumptions for outward side effects.
    # Reserved and consumed rows both count against a quota until exact external
    # reconciliation proves that the effect did not occur.
    "authorization_consumptions": [
        "authorization_digest",
        "protected_action",
        "effect",
        "status",
        "delivery_id",
        "quota_name",
    ],
    # Point-of-use, digest-bound grants for sending private source to a
    # non-local provider.  The committed policy and RunAuthorization are both
    # bound into each record before invocation.
    "source_egress_authorizations": ["provider_id", "packet_id", "authorization_digest"],
    # Content-addressed factory execution observations. These are explicitly not
    # authority ValidationEvidence and cannot close a semantic obligation.
    "factory_validation_receipts": ["obligation_id"],
    # Terminal-completion stability tracker (two consecutive zero-gap snapshots).
    "terminal_stability": [],
    "cycles": ["state"],
    "budget_events": ["cycle_id", "provider_id"],
    "budget_reservations": ["cycle_id", "provider_id", "status", "day"],
    # Runtime-discovered concurrency state.  These records explain admission;
    # they are never semantic authority or configured capacity.
    "adaptive_controller_states": ["controller_session"],
    "adaptive_decisions": ["controller_session", "workload_key"],
    "adaptive_invocations": [
        "controller_session",
        "packet_id",
        "provider_id",
        "workload_key",
        "status",
    ],
    "adaptive_observations": ["workload_key", "provider_id", "actual_model", "task_class"],
    # One compact derived operational summary per completed cycle. Raw invocation
    # and observation records remain the evidence source.
    "operational_summaries": ["cycle_id", "authority_digest", "state"],
    # Latest OBSERVED health per provider (scheduler fact source; never fabricated).
    "provider_health": [],
    # Snapshot-bound materialisation index builds (digest-keyed, per snapshot).
    "materialisation_indexes": ["snapshot_id"],
}

_APPEND_TABLES: dict[str, list[str]] = {
    "events": ["cycle_id", "kind", "stage"],
    "provider_health_events": ["provider_id", "status"],
    "quota_events": ["provider_id"],
    # Immutable raw learning observations (P1-20): scores are derived projections.
    "observations": ["stage", "agent_profile_id", "task_class", "dimension"],
    # Immutable indexes into digest-bound delivery-transition CAS objects.
    "delivery_transitions": ["delivery_id", "state"],
    # Immutable audit trail; authorization_consumptions is only its current
    # projection for atomic quota checks.
    "authorization_consumption_events": [
        "authorization_digest",
        "delivery_id",
        "effect",
        "status",
    ],
    "adaptive_invocation_events": ["controller_session", "packet_id", "status"],
}


class StaleDeliveryTransition(RuntimeError):
    """The caller attempted to update a delivery from an obsolete revision."""


class SideEffectQuotaExceeded(RuntimeError):
    """No authorization-bound capacity remains for the requested side effect."""


class Store:
    """The durable state store. Not thread-safe; use one per process/loop."""

    def __init__(self, db_path: Path, cas_dir: Path) -> None:
        self.db_path = db_path
        self.cas_dir = cas_dir
        db_path.parent.mkdir(parents=True, exist_ok=True)
        cas_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")  # durable across OS crash
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")  # tolerate concurrent writers
        self._create_schema()

    # ---- lifecycle ------------------------------------------------------- #

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
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
                token INTEGER NOT NULL DEFAULT 0,
                claimed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (packet_id, run_id)
            )
            """
        )
        # One compare-and-set head per delivery.  The full immutable transition
        # bytes live in CAS and are indexed in delivery_transitions.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS delivery_transition_heads (
                delivery_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                transition_ref TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_packet_active_claim "
            "ON packet_claims(packet_id) WHERE status = 'active'"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_adaptive_packet_active "
            "ON adaptive_invocations(packet_id) WHERE status = 'active'"
        )
        # Lightweight migration: add token column to pre-existing claim tables.
        claim_cols = {r["name"] for r in cur.execute("PRAGMA table_info(packet_claims)").fetchall()}
        if "token" not in claim_cols:
            cur.execute("ALTER TABLE packet_claims ADD COLUMN token INTEGER NOT NULL DEFAULT 0")
        # Fencing-token source: a monotonically increasing counter. Any lease or
        # claim carries a token; a holder with a stale token is fenced out.
        cur.execute(
            "CREATE TABLE IF NOT EXISTS fencing_tokens ("
            "token INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL)"
        )
        # Named leases (e.g. the sole coordinator lease). Exactly one row per name.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS leases (
                name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                token INTEGER NOT NULL,
                status TEXT NOT NULL,        -- active | released
                acquired_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )

    # ---- fencing tokens & leases ---------------------------------------- #

    def mint_token(self) -> int:
        """Mint a strictly increasing fencing token."""
        cur = self._conn.execute("INSERT INTO fencing_tokens (at) VALUES (?)", (utc_now_iso(),))
        return int(cur.lastrowid or 0)

    def acquire_lease(self, name: str, owner: str, expires_at: str) -> int | None:
        """Acquire a named lease. Returns a fencing token, or None if a live
        lease is held by someone else. An expired lease is superseded."""
        now = utc_now_iso()
        with self.transaction():
            row = self._conn.execute("SELECT * FROM leases WHERE name=?", (name,)).fetchone()
            if row is not None and row["status"] == "active" and row["expires_at"] > now:
                return None  # a live lease is held
            token = self.mint_token()
            self._conn.execute(
                "INSERT INTO leases (name, owner, token, status, acquired_at, heartbeat_at, expires_at) "
                "VALUES (?, ?, ?, 'active', ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET owner=excluded.owner, token=excluded.token, "
                "status='active', acquired_at=excluded.acquired_at, heartbeat_at=excluded.heartbeat_at, "
                "expires_at=excluded.expires_at",
                (name, owner, token, now, now, expires_at),
            )
            return token

    def renew_lease(self, name: str, owner: str, token: int, expires_at: str) -> bool:
        """Heartbeat a lease. Only the current (owner, token) holder may renew;
        a superseded holder is fenced out (returns False)."""
        now = utc_now_iso()
        cur = self._conn.execute(
            "UPDATE leases SET heartbeat_at=?, expires_at=? "
            "WHERE name=? AND owner=? AND token=? AND status='active' AND expires_at>?",
            (now, expires_at, name, owner, token, now),
        )
        return cur.rowcount > 0

    def release_lease(self, name: str, owner: str, token: int) -> None:
        self._conn.execute(
            "UPDATE leases SET status='released' WHERE name=? AND owner=? AND token=?",
            (name, owner, token),
        )

    def lease_token_current(self, name: str, token: int) -> bool:
        """True iff ``token`` is the active token for ``name`` (fencing check)."""
        row = self._conn.execute(
            "SELECT token, status, expires_at FROM leases WHERE name=?", (name,)
        ).fetchone()
        if row is None or row["status"] != "active":
            return False
        return int(row["token"]) == int(token) and row["expires_at"] > utc_now_iso()

    def reap_expired_leases(self) -> list[str]:
        """Mark expired active leases as released; returns reaped names."""
        now = utc_now_iso()
        rows = self._conn.execute(
            "SELECT name FROM leases WHERE status='active' AND expires_at <= ?", (now,)
        ).fetchall()
        names = [r["name"] for r in rows]
        if names:
            self._conn.execute(
                "UPDATE leases SET status='released' WHERE status='active' AND expires_at <= ?",
                (now,),
            )
        return names

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

    def claim_packet_fenced(
        self, packet_id: str, run_id: str, owner: str, expires_at: str
    ) -> int | None:
        """Claim a packet and return its fencing token, or None if already claimed.

        The partial unique index guarantees at most one active claim per packet,
        so a duplicate claim from a retry/crash cannot double-dispatch. The token
        lets result submission be fenced: a crashed/expired worker holding a stale
        token is rejected (see :meth:`claim_token_current`).
        """
        token = self.mint_token()
        try:
            self._conn.execute(
                "INSERT INTO packet_claims (packet_id, run_id, owner, status, token, claimed_at, expires_at) "
                "VALUES (?, ?, ?, 'active', ?, ?, ?)",
                (packet_id, run_id, owner, token, utc_now_iso(), expires_at),
            )
            return token
        except sqlite3.IntegrityError:
            return None

    def claim_packet(self, packet_id: str, run_id: str, owner: str, expires_at: str) -> bool:
        """Boolean claim (back-compat wrapper around :meth:`claim_packet_fenced`)."""
        return self.claim_packet_fenced(packet_id, run_id, owner, expires_at) is not None

    def renew_claim(self, packet_id: str, run_id: str, token: int, expires_at: str) -> bool:
        """Extend an ACTIVE claim's deadline — only for the exact holder (packet,
        run, token). Returns False when the claim was reaped/reassigned, so the
        executor can fence the worker out immediately."""
        now = utc_now_iso()
        cur = self._conn.execute(
            "UPDATE packet_claims SET expires_at=? "
            "WHERE packet_id=? AND run_id=? AND token=? AND status='active' AND expires_at>?",
            (expires_at, packet_id, run_id, token, now),
        )
        return cur.rowcount == 1

    # ---- adaptive invocation admission --------------------------------- #

    def try_admit_invocation(
        self,
        *,
        attempt_id: str,
        packet_id: str,
        run_id: str,
        claim_token: int,
        coordinator_owner: str,
        coordinator_token: int,
        controller_session: str,
        workload_key: str,
        provider_id: str,
        permitted_active: int,
        decision_digest: str,
        payload: dict[str, Any],
    ) -> int | None:
        """Atomically admit one distinct packet under the controller's *current*
        experimental load decision.  ``permitted_active`` is observed state,
        never configuration.  A partial unique index prevents duplicate active
        invocations for one packet across coordinators.
        """
        if permitted_active < 1:
            return None
        now = utc_now_iso()
        with self.transaction(immediate=True):
            coordinator = self._conn.execute(
                "SELECT owner, token, expires_at FROM leases "
                "WHERE name='coordinator' AND status='active'"
            ).fetchone()
            if (
                coordinator is None
                or str(coordinator["owner"]) != coordinator_owner
                or int(coordinator["token"]) != int(coordinator_token)
                or str(coordinator["expires_at"]) <= now
            ):
                return None
            state = self.get("adaptive_controller_states", controller_session)
            if (
                state is None
                or int(state.get("permitted_active") or 0) != permitted_active
                or state.get("decision_digest") != decision_digest
            ):
                return None
            claim = self._conn.execute(
                "SELECT token, expires_at FROM packet_claims "
                "WHERE packet_id=? AND run_id=? AND status='active'",
                (packet_id, run_id),
            ).fetchone()
            if (
                claim is None
                or int(claim["token"]) != int(claim_token)
                or str(claim["expires_at"]) <= now
            ):
                return None
            existing = self.get("adaptive_invocations", attempt_id)
            if existing is not None:
                if (
                    existing.get("packet_id") == packet_id
                    and existing.get("run_id") == run_id
                    and existing.get("controller_session") == controller_session
                    and existing.get("status") == "active"
                ):
                    return int(existing.get("admission_token") or 0)
                raise ValueError("ADAPTIVE_INVOCATION_IDEMPOTENCY_MISMATCH")
            active = self.count("adaptive_invocations", "status='active'")
            if active >= permitted_active:
                return None
            token = self.mint_token()
            admitted = {
                **payload,
                "schema_version": 1,
                "attempt_id": attempt_id,
                "packet_id": packet_id,
                "run_id": run_id,
                "claim_token": claim_token,
                "coordinator_owner": coordinator_owner,
                "coordinator_token": coordinator_token,
                "controller_session": controller_session,
                "workload_key": workload_key,
                "provider_id": provider_id,
                "permitted_active": permitted_active,
                "observed_active_before": active,
                "decision_digest": decision_digest,
                "admission_token": token,
                "status": "active",
                "admitted_at": now,
                "settled_at": "",
            }
            try:
                self.put(
                    "adaptive_invocations",
                    attempt_id,
                    admitted,
                    extra={
                        "controller_session": controller_session,
                        "packet_id": packet_id,
                        "provider_id": provider_id,
                        "workload_key": workload_key,
                        "status": "active",
                    },
                )
            except sqlite3.IntegrityError:
                return None
            self.append(
                "adaptive_invocation_events",
                admitted,
                extra={
                    "controller_session": controller_session,
                    "packet_id": packet_id,
                    "status": "active",
                },
            )
            return token

    def settle_invocation(
        self,
        *,
        attempt_id: str,
        admission_token: int,
        status: str,
        observation: dict[str, Any],
    ) -> bool:
        """Settle an invocation exactly once and append its observation."""
        if status not in {"completed", "failed", "timed_out", "fenced", "uncertain"}:
            raise ValueError("ADAPTIVE_INVOCATION_STATUS_INVALID")
        with self.transaction(immediate=True):
            row = self.get("adaptive_invocations", attempt_id)
            if row is None or int(row.get("admission_token") or 0) != admission_token:
                return False
            if row.get("status") != "active":
                return row.get("status") == status
            settled = {**row, "status": status, "settled_at": utc_now_iso()}
            self.put(
                "adaptive_invocations",
                attempt_id,
                settled,
                extra={
                    "controller_session": str(row["controller_session"]),
                    "packet_id": str(row["packet_id"]),
                    "provider_id": str(row["provider_id"]),
                    "workload_key": str(row["workload_key"]),
                    "status": status,
                },
            )
            observed = {**observation, "attempt_id": attempt_id, "status": status}
            self.put(
                "adaptive_observations",
                attempt_id,
                observed,
                extra={
                    "workload_key": str(observed.get("workload_key") or ""),
                    "provider_id": str(observed.get("provider_id") or ""),
                    "actual_model": str(observed.get("actual_model") or ""),
                    "task_class": str(observed.get("task_class") or ""),
                },
            )
            self.append(
                "adaptive_invocation_events",
                {**settled, "observation_digest": digest_bytes(canonical_json(observed).encode())},
                extra={
                    "controller_session": str(row["controller_session"]),
                    "packet_id": str(row["packet_id"]),
                    "status": status,
                },
            )
            return True

    def reconcile_adaptive_invocations(self, current_session: str) -> dict[str, list[str]]:
        """Reconcile previous-session invocations without assuming cancellation.

        Only an attempt whose durable packet claim reached its timeout boundary
        is irrecoverably unavailable and may be fenced automatically. An active,
        released or missing claim leaves the attempt pending and blocks new work;
        otherwise a still-running provider call could be duplicated.
        """
        fenced_ids: list[str] = []
        pending_ids: list[str] = []
        with self.transaction(immediate=True):
            rows = self.items(
                "adaptive_invocations",
                "status='active' AND controller_session!=?",
                (current_session,),
            )
            for attempt_id, row in rows:
                claim = self._conn.execute(
                    "SELECT status, expires_at FROM packet_claims WHERE packet_id=? AND run_id=?",
                    (str(row.get("packet_id") or ""), str(row.get("run_id") or "")),
                ).fetchone()
                if claim is None or str(claim["status"]) != "expired":
                    pending_ids.append(attempt_id)
                    continue
                fenced = {**row, "status": "fenced", "settled_at": utc_now_iso()}
                self.put(
                    "adaptive_invocations",
                    attempt_id,
                    fenced,
                    extra={
                        "controller_session": str(row["controller_session"]),
                        "packet_id": str(row["packet_id"]),
                        "provider_id": str(row["provider_id"]),
                        "workload_key": str(row["workload_key"]),
                        "status": "fenced",
                    },
                )
                self.append(
                    "adaptive_invocation_events",
                    fenced,
                    extra={
                        "controller_session": str(row["controller_session"]),
                        "packet_id": str(row["packet_id"]),
                        "status": "fenced",
                    },
                )
                fenced_ids.append(attempt_id)
        return {"fenced": fenced_ids, "pending": pending_ids}

    def record_adaptive_outcome(
        self,
        *,
        attempt_id: str,
        accepted: bool,
        validated: bool,
        independently_reviewed: bool | None,
    ) -> bool:
        """Append and project the independently qualified invocation outcome.

        Provider completion and factory acceptance are separate observations.
        This operation preserves both rather than silently rewriting the only
        durable record after validation finishes.
        """
        with self.transaction(immediate=True):
            invocation = self.get("adaptive_invocations", attempt_id)
            observation = self.get("adaptive_observations", attempt_id)
            if invocation is None or observation is None:
                return False
            updated = {
                **observation,
                "accepted": bool(accepted),
                "validated": bool(accepted and validated),
                "semantic_rejected": not accepted,
                "independent_review_accepted": independently_reviewed,
            }
            observation_digest = digest_bytes(canonical_json(updated).encode())
            self.put(
                "adaptive_observations",
                attempt_id,
                updated,
                digest=observation_digest,
                extra={
                    "workload_key": str(updated.get("workload_key") or ""),
                    "provider_id": str(updated.get("provider_id") or ""),
                    "actual_model": str(updated.get("actual_model") or ""),
                    "task_class": str(updated.get("task_class") or ""),
                },
            )
            self.append(
                "adaptive_invocation_events",
                {
                    "schema_version": 1,
                    "attempt_id": attempt_id,
                    "packet_id": str(invocation.get("packet_id") or ""),
                    "controller_session": str(invocation.get("controller_session") or ""),
                    "status": "validated",
                    "accepted": bool(accepted),
                    "validated": bool(accepted and validated),
                    "observation_digest": observation_digest,
                },
                extra={
                    "controller_session": str(invocation.get("controller_session") or ""),
                    "packet_id": str(invocation.get("packet_id") or ""),
                    "status": "validated",
                },
            )
            return True

    # ---- atomic delivery transitions and side-effect quotas ------------- #

    def persist_delivery_transition(
        self,
        *,
        delivery_id: str,
        expected_revision: int,
        record_payload: dict[str, Any],
        from_state: str,
        to_state: str,
        input_ref: str,
        assurance_bundle_ref: str,
        authorization_digest: str,
        note_code: str,
        reservation: dict[str, Any] | None = None,
        consume_id: str | None = None,
        release_id: str | None = None,
    ) -> tuple[int, str]:
        """Atomically append a CAS transition, advance its compare-and-set head,
        update the current DeliveryRecord projection, and reserve/reconcile an
        irreversible-action quota.

        CAS bytes are written before the SQLite transaction.  A database failure
        can therefore leave only an unreferenced immutable blob, which the
        existing CAS garbage collector may safely remove; it cannot leave a
        projection without its transition.
        """

        next_revision = expected_revision + 1
        prior = self._conn.execute(
            "SELECT revision, transition_ref, state FROM delivery_transition_heads "
            "WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()
        previous_transition_ref = str(prior["transition_ref"]) if prior is not None else ""
        projected = dict(record_payload)
        projected["version"] = next_revision
        projected.pop("transition_ref", None)
        transition_payload = {
            "schema_version": 1,
            "delivery_id": delivery_id,
            "revision": next_revision,
            "previous_transition_ref": previous_transition_ref,
            "from_state": from_state,
            "to_state": to_state,
            "input_ref": input_ref,
            "assurance_bundle_ref": assurance_bundle_ref,
            "authorization_digest": authorization_digest,
            "effect": str((reservation or {}).get("effect") or ""),
            "consumption_id": str((reservation or {}).get("consumption_id") or consume_id or ""),
            "note_code": note_code,
            # Do not embed transition_ref here: that would make the CAS object
            # recursively self-referential.
            "delivery_record": projected,
        }
        transition_ref = self.cas_put_text(canonical_json(transition_payload))
        projected["transition_ref"] = transition_ref

        with self.transaction(immediate=True):
            head = self._conn.execute(
                "SELECT revision, transition_ref, state FROM delivery_transition_heads "
                "WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            current_revision = int(head["revision"]) if head is not None else 0
            if current_revision != expected_revision:
                raise StaleDeliveryTransition(
                    f"DELIVERY_TRANSITION_STALE:{delivery_id}:{expected_revision}:{current_revision}"
                )
            current_ref = str(head["transition_ref"]) if head is not None else ""
            current_state = str(head["state"]) if head is not None else ""
            if current_ref != previous_transition_ref or current_state != from_state:
                raise StaleDeliveryTransition(
                    f"DELIVERY_TRANSITION_PRIOR_MISMATCH:{delivery_id}:{from_state}:{current_state}"
                )

            if reservation is not None:
                consumption_id = str(reservation["consumption_id"])
                existing = self.get("authorization_consumptions", consumption_id)
                if existing is None:
                    quota_name = str(reservation.get("quota_name") or "")
                    quota_limit = reservation.get("quota_limit")
                    if quota_name and quota_limit is not None:
                        row = self._conn.execute(
                            "SELECT COUNT(*) AS n FROM authorization_consumptions "
                            "WHERE authorization_digest=? AND quota_name=? "
                            "AND status IN ('reserved','consumed')",
                            (authorization_digest, quota_name),
                        ).fetchone()
                        if int(row["n"]) >= int(quota_limit):
                            raise SideEffectQuotaExceeded(
                                f"SIDE_EFFECT_QUOTA_EXCEEDED:{quota_name}:{quota_limit}"
                            )
                    payload = {
                        **reservation,
                        "schema_version": 1,
                        "authorization_digest": authorization_digest,
                        "delivery_id": delivery_id,
                        "status": "reserved",
                        "reserved_transition_ref": transition_ref,
                        "consumed_transition_ref": "",
                        "released_transition_ref": "",
                    }
                    self.put(
                        "authorization_consumptions",
                        consumption_id,
                        payload,
                        extra={
                            "authorization_digest": authorization_digest,
                            "protected_action": str(payload.get("protected_action") or ""),
                            "effect": str(payload.get("effect") or ""),
                            "status": "reserved",
                            "delivery_id": delivery_id,
                            "quota_name": quota_name,
                        },
                    )
                    self.append(
                        "authorization_consumption_events",
                        payload,
                        extra={
                            "authorization_digest": authorization_digest,
                            "delivery_id": delivery_id,
                            "effect": str(payload.get("effect") or ""),
                            "status": "reserved",
                        },
                    )
                elif (
                    existing.get("authorization_digest") != authorization_digest
                    or existing.get("delivery_id") != delivery_id
                    or existing.get("effect") != reservation.get("effect")
                ):
                    raise ValueError("SIDE_EFFECT_IDEMPOTENCY_BINDING_MISMATCH")

            if consume_id:
                existing = self.get("authorization_consumptions", consume_id)
                if existing is None or existing.get("status") not in {"reserved", "consumed"}:
                    raise ValueError("SIDE_EFFECT_RESERVATION_MISSING")
                if existing.get("status") == "reserved":
                    existing = {
                        **existing,
                        "status": "consumed",
                        "consumed_transition_ref": transition_ref,
                    }
                    self.put(
                        "authorization_consumptions",
                        consume_id,
                        existing,
                        extra={
                            "authorization_digest": existing["authorization_digest"],
                            "protected_action": existing["protected_action"],
                            "effect": existing["effect"],
                            "status": "consumed",
                            "delivery_id": existing["delivery_id"],
                            "quota_name": existing.get("quota_name", ""),
                        },
                    )
                    self.append(
                        "authorization_consumption_events",
                        existing,
                        extra={
                            "authorization_digest": str(existing["authorization_digest"]),
                            "delivery_id": str(existing["delivery_id"]),
                            "effect": str(existing["effect"]),
                            "status": "consumed",
                        },
                    )

            if release_id:
                existing = self.get("authorization_consumptions", release_id)
                if existing is None or existing.get("status") != "reserved":
                    raise ValueError("SIDE_EFFECT_RESERVATION_NOT_RELEASABLE")
                existing = {
                    **existing,
                    "status": "released",
                    "released_transition_ref": transition_ref,
                }
                self.put(
                    "authorization_consumptions",
                    release_id,
                    existing,
                    extra={
                        "authorization_digest": existing["authorization_digest"],
                        "protected_action": existing["protected_action"],
                        "effect": existing["effect"],
                        "status": "released",
                        "delivery_id": existing["delivery_id"],
                        "quota_name": existing.get("quota_name", ""),
                    },
                )
                self.append(
                    "authorization_consumption_events",
                    existing,
                    extra={
                        "authorization_digest": str(existing["authorization_digest"]),
                        "delivery_id": str(existing["delivery_id"]),
                        "effect": str(existing["effect"]),
                        "status": "released",
                    },
                )

            self.append(
                "delivery_transitions",
                {**transition_payload, "transition_ref": transition_ref},
                extra={"delivery_id": delivery_id, "state": to_state},
            )
            self._conn.execute(
                "INSERT INTO delivery_transition_heads "
                "(delivery_id, revision, transition_ref, state, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(delivery_id) DO UPDATE SET "
                "revision=excluded.revision, transition_ref=excluded.transition_ref, "
                "state=excluded.state, updated_at=excluded.updated_at",
                (delivery_id, next_revision, transition_ref, to_state, utc_now_iso()),
            )
            self.put(
                "delivery_records",
                delivery_id,
                projected,
                extra={
                    "obligation_id": str(projected.get("obligation_id") or ""),
                    "state": to_state,
                },
            )
        return next_revision, transition_ref

    def claim_token_current(self, packet_id: str, token: int) -> bool:
        """True iff ``token`` matches the active, unexpired claim for the packet."""
        row = self._conn.execute(
            "SELECT token, expires_at FROM packet_claims WHERE packet_id=? AND status='active'",
            (packet_id,),
        ).fetchone()
        if row is None:
            return False
        return int(row["token"]) == int(token) and row["expires_at"] > utc_now_iso()

    def release_packet(self, packet_id: str, run_id: str) -> None:
        self._conn.execute(
            "UPDATE packet_claims SET status='released' WHERE packet_id=? AND run_id=?",
            (packet_id, run_id),
        )

    def reap_expired_claims(self) -> list[str]:
        """Mark expired active claims as released; returns reclaimed packet ids."""
        now = utc_now_iso()
        rows = self._conn.execute(
            "SELECT packet_id FROM packet_claims WHERE status='active' AND expires_at <= ?", (now,)
        ).fetchall()
        ids = [r["packet_id"] for r in rows]
        if ids:
            self._conn.execute(
                "UPDATE packet_claims SET status='expired' WHERE status='active' AND expires_at <= ?",
                (now,),
            )
        return ids

    def active_claim(self, packet_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM packet_claims WHERE packet_id=? AND status='active'",
            (packet_id,),
        ).fetchone()
        return dict(row) if row else None

    # ---- content-addressed store ---------------------------------------- #

    def cas_put(self, data: bytes) -> str:
        """Store bytes durably; returns a ``cas:sha256:...`` reference.

        Crash-safe: write to a unique temp file, fsync it, atomically rename,
        fsync the directory, then verify the stored digest by read-back.
        """
        dg = digest_bytes(data)  # sha256:hex
        hexpart = dg.split(":", 1)[1]
        shard = self.cas_dir / hexpart[:2] / hexpart[2:4]
        shard.mkdir(parents=True, exist_ok=True)
        target = shard / hexpart
        if not target.exists():
            fd, tmpname = tempfile.mkstemp(dir=str(shard), prefix=".cas.", suffix=".tmp")
            tmp_path = Path(tmpname)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                tmp_path.replace(target)
                dirfd = os.open(str(shard), os.O_DIRECTORY)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()
        # Read-back integrity verification.
        if digest_bytes(target.read_bytes()) != dg:
            raise OSError(f"CAS integrity check failed for {dg}")
        return f"cas:{dg}"

    def cas_put_text(self, text: str) -> str:
        return self.cas_put(text.encode("utf-8"))

    def cas_get(self, ref: str) -> bytes:
        if not ref.startswith("cas:sha256:"):
            raise ValueError(f"invalid CAS ref: {ref}")
        hexpart = ref.split("sha256:", 1)[1]
        target = self.cas_dir / hexpart[:2] / hexpart[2:4] / hexpart
        data = target.read_bytes()
        if digest_bytes(data) != f"sha256:{hexpart}":
            raise OSError(f"CAS integrity check failed on read for {ref}")
        return data

    def referenced_cas_refs(self) -> set[str]:
        """Transitive closure of CAS references rooted in durable SQLite state."""
        import re

        pat = re.compile(r"cas:sha256:[0-9a-f]{64}")
        refs: set[str] = set()
        tables = list(_RECORD_TABLES) + list(_APPEND_TABLES)
        for table in tables:
            for row in self._conn.execute(f"SELECT payload FROM {table}").fetchall():
                refs.update(pat.findall(row["payload"]))
        pending = list(refs)
        visited: set[str] = set()
        while pending:
            ref = pending.pop()
            if ref in visited:
                continue
            visited.add(ref)
            try:
                text = self.cas_get(ref).decode("utf-8")
            except (OSError, UnicodeDecodeError, ValueError):
                continue
            for child in pat.findall(text):
                if child not in refs:
                    refs.add(child)
                    pending.append(child)
        return refs

    def cas_gc(self) -> int:
        """Delete CAS blobs not referenced by any stored payload. Returns count."""
        referenced_hex = {r.split("sha256:", 1)[1] for r in self.referenced_cas_refs()}
        removed = 0
        for shard1 in self.cas_dir.iterdir() if self.cas_dir.exists() else []:
            if not shard1.is_dir():
                continue
            for shard2 in shard1.iterdir():
                if not shard2.is_dir():
                    continue
                for blob in shard2.iterdir():
                    if blob.is_file() and blob.name not in referenced_hex:
                        blob.unlink()
                        removed += 1
        return removed

    def backup(self, dest: Path) -> None:
        """Consistent online backup of the SQLite database via the backup API."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(dest)) as bck:
            self._conn.backup(bck)

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
