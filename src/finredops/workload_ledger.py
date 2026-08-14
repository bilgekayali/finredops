"""Append-only one-time test-account grant consumption ledger."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import ensure_aware

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")


class WorkloadLedgerError(RuntimeError):
    """Raised when one-time grant consumption cannot be recorded safely."""


class SQLiteOneTimeGrantLedger:
    """Persist one irreversible consumption record per institution/grant digest."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workload_grant_consumption (
                    institution_id TEXT NOT NULL,
                    grant_digest TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    PRIMARY KEY (institution_id, grant_digest)
                ) WITHOUT ROWID
                """
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def consume_once(
        self,
        *,
        institution_id: str,
        grant_digest: str,
        lease_id: str,
        consumed_at: datetime,
    ) -> bool:
        if not isinstance(institution_id, str) or not _ID.fullmatch(institution_id):
            raise WorkloadLedgerError("institution_id is invalid.")
        if not isinstance(lease_id, str) or not _ID.fullmatch(lease_id):
            raise WorkloadLedgerError("lease_id is invalid.")
        if not isinstance(grant_digest, str) or not _DIGEST.fullmatch(grant_digest):
            raise WorkloadLedgerError("grant_digest must be SHA-256.")
        timestamp = ensure_aware(consumed_at).isoformat().replace("+00:00", "Z")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO workload_grant_consumption
                        (institution_id, grant_digest, lease_id, consumed_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (institution_id, grant_digest, lease_id, timestamp),
                )
                connection.commit()
                return True
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise WorkloadLedgerError("Could not persist one-time grant consumption.") from exc

    def consumed(self, *, institution_id: str, grant_digest: str) -> bool:
        if not isinstance(institution_id, str) or not _ID.fullmatch(institution_id):
            raise WorkloadLedgerError("institution_id is invalid.")
        if not isinstance(grant_digest, str) or not _DIGEST.fullmatch(grant_digest):
            raise WorkloadLedgerError("grant_digest must be SHA-256.")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM workload_grant_consumption
                WHERE institution_id = ? AND grant_digest = ?
                """,
                (institution_id, grant_digest),
            ).fetchone()
        return row is not None
