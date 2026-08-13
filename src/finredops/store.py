"""Transactional SQLite persistence with institution-scoped isolation."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .audit import AuditChain, GENESIS_HASH
from .models import canonical_json, ensure_aware, sha256_digest, to_primitive

_INSTITUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")


class PersistenceConflict(RuntimeError):
    """Raised when durable state diverges or an idempotency key is reused."""


def _validate_institution_id(value: str) -> str:
    if not isinstance(value, str) or not _INSTITUTION_ID.fullmatch(value):
        raise ValueError("institution_id is not a valid bounded identifier.")
    return value


@dataclass(frozen=True, slots=True)
class PersistedSnapshot:
    engagement_id: str
    revision: int
    snapshot_digest: str
    created_at: datetime
    institution_id: str = "default"


class SQLiteGovernanceStore:
    """Durable store whose every record is scoped to one bound institution.

    A store handle is created for exactly one ``institution_id``. Callers cannot
    pass an alternate tenant to individual reads or writes, which reduces the
    chance that application code accidentally performs an unscoped query.

    Schema v2 migrates legacy v1 rows into the explicit ``default`` institution.
    This is an isolation boundary only; it does not claim encryption at rest.
    """

    schema_version = 2

    def __init__(self, path: str | Path, *, institution_id: str = "default") -> None:
        self.path = str(path)
        self.institution_id = _validate_institution_id(institution_id)
        self._connection = sqlite3.connect(self.path, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def _create_v2_schema(self) -> None:
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE engagement_snapshots (
                institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision > 0),
                snapshot_json TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                created_at TEXT NOT NULL,
                PRIMARY KEY (institution_id, engagement_id, revision),
                UNIQUE (institution_id, engagement_id, snapshot_digest)
            );
            CREATE TABLE audit_events (
                institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                event_json TEXT NOT NULL,
                event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                PRIMARY KEY (institution_id, engagement_id, sequence),
                UNIQUE (institution_id, engagement_id, event_hash)
            );
            CREATE TABLE idempotency_records (
                institution_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                created_at TEXT NOT NULL,
                PRIMARY KEY (institution_id, idempotency_key)
            );
            CREATE INDEX idx_snapshot_latest
                ON engagement_snapshots (institution_id, engagement_id, revision DESC);
            PRAGMA user_version = 2;
            COMMIT;
            """
        )

    def _migrate_v1_to_v2(self) -> None:
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;
            ALTER TABLE engagement_snapshots RENAME TO engagement_snapshots_v1;
            ALTER TABLE audit_events RENAME TO audit_events_v1;
            ALTER TABLE idempotency_records RENAME TO idempotency_records_v1;
            DROP INDEX IF EXISTS idx_snapshot_latest;

            CREATE TABLE engagement_snapshots (
                institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision > 0),
                snapshot_json TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                created_at TEXT NOT NULL,
                PRIMARY KEY (institution_id, engagement_id, revision),
                UNIQUE (institution_id, engagement_id, snapshot_digest)
            );
            CREATE TABLE audit_events (
                institution_id TEXT NOT NULL,
                engagement_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                event_json TEXT NOT NULL,
                event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                PRIMARY KEY (institution_id, engagement_id, sequence),
                UNIQUE (institution_id, engagement_id, event_hash)
            );
            CREATE TABLE idempotency_records (
                institution_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                created_at TEXT NOT NULL,
                PRIMARY KEY (institution_id, idempotency_key)
            );

            INSERT INTO engagement_snapshots
                (institution_id, engagement_id, revision, snapshot_json, snapshot_digest, created_at)
            SELECT 'default', engagement_id, revision, snapshot_json, snapshot_digest, created_at
            FROM engagement_snapshots_v1;

            INSERT INTO audit_events
                (institution_id, engagement_id, sequence, event_json, event_hash, previous_hash)
            SELECT 'default', engagement_id, sequence, event_json, event_hash, previous_hash
            FROM audit_events_v1;

            INSERT INTO idempotency_records
                (institution_id, idempotency_key, request_digest, result_digest, created_at)
            SELECT 'default', idempotency_key, request_digest, result_digest, created_at
            FROM idempotency_records_v1;

            DROP TABLE engagement_snapshots_v1;
            DROP TABLE audit_events_v1;
            DROP TABLE idempotency_records_v1;
            CREATE INDEX idx_snapshot_latest
                ON engagement_snapshots (institution_id, engagement_id, revision DESC);
            PRAGMA user_version = 2;
            COMMIT;
            """
        )

    def _migrate(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version > self.schema_version:
            raise RuntimeError(
                f"Database schema {version} is newer than supported {self.schema_version}."
            )
        if version == 0:
            self._create_v2_schema()
        elif version == 1:
            self._migrate_v1_to_v2()

    def save_snapshot(
        self, snapshot: Mapping[str, Any], *, now: datetime
    ) -> PersistedSnapshot:
        now = ensure_aware(now)
        if snapshot.get("schema_version") != "finredops.snapshot.v2":
            raise ValueError("Only FinRedOps v2 snapshots can be persisted.")
        engagement = snapshot.get("engagement")
        if not isinstance(engagement, Mapping) or not engagement.get("engagement_id"):
            raise ValueError("Snapshot is missing its engagement identity.")
        engagement_id = str(engagement["engagement_id"])
        document = canonical_json(snapshot)
        digest = sha256_digest(snapshot)
        created_at = now.isoformat().replace("+00:00", "Z")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            existing = self._connection.execute(
                """
                SELECT revision, snapshot_digest, created_at
                FROM engagement_snapshots
                WHERE institution_id = ? AND engagement_id = ? AND snapshot_digest = ?
                """,
                (self.institution_id, engagement_id, digest),
            ).fetchone()
            if existing:
                self._connection.execute("COMMIT")
                return PersistedSnapshot(
                    engagement_id=engagement_id,
                    revision=int(existing["revision"]),
                    snapshot_digest=str(existing["snapshot_digest"]),
                    created_at=datetime.fromisoformat(
                        str(existing["created_at"]).replace("Z", "+00:00")
                    ),
                    institution_id=self.institution_id,
                )
            row = self._connection.execute(
                """
                SELECT COALESCE(MAX(revision), 0) + 1
                FROM engagement_snapshots
                WHERE institution_id = ? AND engagement_id = ?
                """,
                (self.institution_id, engagement_id),
            ).fetchone()
            revision = int(row[0])
            self._connection.execute(
                """
                INSERT INTO engagement_snapshots
                    (institution_id, engagement_id, revision, snapshot_json, snapshot_digest, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self.institution_id,
                    engagement_id,
                    revision,
                    document,
                    digest,
                    created_at,
                ),
            )
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return PersistedSnapshot(
            engagement_id, revision, digest, now, institution_id=self.institution_id
        )

    def load_latest(self, engagement_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            """
            SELECT snapshot_json FROM engagement_snapshots
            WHERE institution_id = ? AND engagement_id = ?
            ORDER BY revision DESC LIMIT 1
            """,
            (self.institution_id, engagement_id),
        ).fetchone()
        return json.loads(row["snapshot_json"]) if row else None

    def list_engagements(self) -> tuple[dict[str, Any], ...]:
        rows = self._connection.execute(
            """
            SELECT s.engagement_id, s.revision, s.snapshot_digest, s.created_at
            FROM engagement_snapshots s
            INNER JOIN (
                SELECT engagement_id, MAX(revision) revision
                FROM engagement_snapshots
                WHERE institution_id = ?
                GROUP BY engagement_id
            ) latest
              ON latest.engagement_id = s.engagement_id AND latest.revision = s.revision
            WHERE s.institution_id = ?
            ORDER BY s.engagement_id
            """,
            (self.institution_id, self.institution_id),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def persist_audit_chain(self, engagement_id: str, chain: AuditChain) -> int:
        valid, errors = chain.verify()
        if not valid:
            raise ValueError("Cannot persist an invalid audit chain: " + " ".join(errors))
        if any(event.engagement_id != engagement_id for event in chain.events):
            raise ValueError("Audit chain contains an event for a different engagement.")
        incoming = [canonical_json(event) for event in chain.events]
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            rows = self._connection.execute(
                """
                SELECT sequence, event_json FROM audit_events
                WHERE institution_id = ? AND engagement_id = ? ORDER BY sequence
                """,
                (self.institution_id, engagement_id),
            ).fetchall()
            for index, row in enumerate(rows):
                if index >= len(incoming) or row["event_json"] != incoming[index]:
                    raise PersistenceConflict(
                        "Persisted audit history is not an exact prefix of the incoming chain."
                    )
            for event, document in zip(chain.events[len(rows) :], incoming[len(rows) :]):
                self._connection.execute(
                    """
                    INSERT INTO audit_events
                        (institution_id, engagement_id, sequence, event_json, event_hash, previous_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.institution_id,
                        engagement_id,
                        event.sequence,
                        document,
                        event.event_hash,
                        event.previous_hash,
                    ),
                )
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return len(incoming) - len(rows)

    def verify_persisted_audit(self, engagement_id: str) -> tuple[bool, tuple[str, ...]]:
        rows = self._connection.execute(
            """
            SELECT event_json FROM audit_events
            WHERE institution_id = ? AND engagement_id = ? ORDER BY sequence
            """,
            (self.institution_id, engagement_id),
        ).fetchall()
        if not rows:
            return False, ("No persisted audit events exist for the engagement in this institution.",)
        chain = AuditChain.from_jsonl("\n".join(str(row["event_json"]) for row in rows))
        valid, errors = chain.verify()
        if chain.events and chain.events[0].previous_hash != GENESIS_HASH:
            return False, (*errors, "Persisted audit chain does not begin at genesis.")
        if any(event.engagement_id != engagement_id for event in chain.events):
            return False, (*errors, "Persisted audit chain contains a different engagement id.")
        return valid and not errors, errors

    def record_idempotency(
        self,
        key: str,
        *,
        request: Mapping[str, Any],
        result: Mapping[str, Any],
        now: datetime,
    ) -> bool:
        if not 16 <= len(key) <= 128 or not all(
            character.isalnum() or character in "-_." for character in key
        ):
            raise ValueError("Idempotency key must contain 16 to 128 safe characters.")
        now = ensure_aware(now)
        request_digest = sha256_digest(request)
        result_digest = sha256_digest(result)
        existing = self._connection.execute(
            """
            SELECT request_digest, result_digest FROM idempotency_records
            WHERE institution_id = ? AND idempotency_key = ?
            """,
            (self.institution_id, key),
        ).fetchone()
        if existing:
            if (
                existing["request_digest"] != request_digest
                or existing["result_digest"] != result_digest
            ):
                raise PersistenceConflict("Idempotency key was reused for different content.")
            return False
        self._connection.execute(
            """
            INSERT INTO idempotency_records
                (institution_id, idempotency_key, request_digest, result_digest, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                self.institution_id,
                key,
                request_digest,
                result_digest,
                now.isoformat().replace("+00:00", "Z"),
            ),
        )
        return True

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "SQLiteGovernanceStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def metadata(self) -> dict[str, Any]:
        return {
            "backend": "sqlite",
            "schema_version": self.schema_version,
            "path": self.path,
            "institution_id": self.institution_id,
            "tenant_scope_enforced": True,
            "encryption_at_rest_verified": False,
            "engagements": [to_primitive(item) for item in self.list_engagements()],
        }
