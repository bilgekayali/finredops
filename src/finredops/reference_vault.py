"""Reference SQLite persistence for encrypted evidence-vault records.

This backend is institution-scoped and append-only at the application API. It is
not claimed to be physical WORM storage. Production deployments can implement
the EvidenceVaultBackend protocol over institution-approved immutable storage.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evidence_vault import (
    EvidenceVaultBackend,
    EvidenceVaultError,
    EvidenceVaultRecord,
    VaultCustodyEvent,
    custody_event_from_document,
    vault_record_from_document,
    verify_vault_history,
)
from .models import canonical_json

_SCHEMA_VERSION = 1


class SQLiteEvidenceVaultBackend(EvidenceVaultBackend):
    """Tenant-bound encrypted reference vault with append-only custody rows."""

    def __init__(self, path: str | Path, *, institution_id: str) -> None:
        if not isinstance(institution_id, str) or not institution_id.strip():
            raise EvidenceVaultError("institution_id is required for the evidence vault backend.")
        self.path = Path(path)
        self.institution_id = institution_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self.path))
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._initialize()
        self._harden_permissions()

    def __enter__(self) -> "SQLiteEvidenceVaultBackend":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _initialize(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise EvidenceVaultError(
                f"Unsupported evidence-vault SQLite schema version {version}."
            )
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_vault_records (
                    institution_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    PRIMARY KEY (institution_id, evidence_id)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_vault_events (
                    institution_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    PRIMARY KEY (institution_id, evidence_id, sequence),
                    UNIQUE (institution_id, evidence_id, event_hash),
                    FOREIGN KEY (institution_id, evidence_id)
                        REFERENCES evidence_vault_records (institution_id, evidence_id)
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_vault_engagement "
                "ON evidence_vault_records (institution_id, engagement_id, evidence_id)"
            )
            self._connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _harden_permissions(self) -> None:
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            # Filesystem ACLs may be controlled outside the process. Runtime
            # metadata does not claim permission verification in that case.
            pass

    def create(self, record: EvidenceVaultRecord, initial_event: VaultCustodyEvent) -> None:
        self._assert_record(record)
        verify_vault_history(record, (initial_event,))
        if initial_event.sequence != 1:
            raise EvidenceVaultError("Initial vault event must have sequence 1.")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                INSERT INTO evidence_vault_records
                    (institution_id, evidence_id, engagement_id, record_json, record_digest)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.institution_id,
                    record.evidence_id,
                    record.engagement_id,
                    canonical_json(record.as_dict()),
                    record.digest(),
                ),
            )
            self._insert_event(initial_event)
            self._connection.commit()
        except sqlite3.IntegrityError as exc:
            self._connection.rollback()
            raise EvidenceVaultError("Evidence identifier already exists in this institution vault.") from exc
        except Exception:
            self._connection.rollback()
            raise

    def load_record(self, evidence_id: str) -> EvidenceVaultRecord:
        row = self._connection.execute(
            """
            SELECT record_json FROM evidence_vault_records
            WHERE institution_id = ? AND evidence_id = ?
            """,
            (self.institution_id, evidence_id),
        ).fetchone()
        if row is None:
            raise EvidenceVaultError("Evidence does not exist in this institution vault.")
        try:
            record = vault_record_from_document(json.loads(row["record_json"]))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EvidenceVaultError("Persisted evidence-vault record is invalid.") from exc
        self._assert_record(record)
        return record

    def load_events(self, evidence_id: str) -> tuple[VaultCustodyEvent, ...]:
        rows = self._connection.execute(
            """
            SELECT event_json FROM evidence_vault_events
            WHERE institution_id = ? AND evidence_id = ?
            ORDER BY sequence ASC
            """,
            (self.institution_id, evidence_id),
        ).fetchall()
        if not rows:
            raise EvidenceVaultError("Evidence custody history is missing.")
        try:
            return tuple(custody_event_from_document(json.loads(row["event_json"])) for row in rows)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EvidenceVaultError("Persisted evidence custody history is invalid.") from exc

    def append_event(self, event: VaultCustodyEvent) -> None:
        if event.institution_id != self.institution_id:
            raise EvidenceVaultError("Custody event belongs to another institution.")
        record = self.load_record(event.evidence_id)
        if event.engagement_id != record.engagement_id:
            raise EvidenceVaultError("Custody event engagement does not match the vault record.")
        current = self.load_events(event.evidence_id)
        prospective = (*current, event)
        verify_vault_history(record, prospective)
        if event.sequence != len(current) + 1 or event.previous_hash != current[-1].digest():
            raise EvidenceVaultError("Custody append does not extend the current persisted head.")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            head = self._connection.execute(
                """
                SELECT sequence, event_hash FROM evidence_vault_events
                WHERE institution_id = ? AND evidence_id = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (self.institution_id, event.evidence_id),
            ).fetchone()
            if head is None or int(head["sequence"]) != event.sequence - 1:
                raise EvidenceVaultError("Custody head changed concurrently.")
            if str(head["event_hash"]) != event.previous_hash:
                raise EvidenceVaultError("Custody head hash changed concurrently.")
            self._insert_event(event)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def restore(self, record: EvidenceVaultRecord, events: Sequence[VaultCustodyEvent]) -> None:
        self._assert_record(record)
        events = tuple(events)
        verify_vault_history(record, events)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            existing = self._connection.execute(
                "SELECT 1 FROM evidence_vault_records WHERE institution_id = ? AND evidence_id = ?",
                (self.institution_id, record.evidence_id),
            ).fetchone()
            if existing is not None:
                raise EvidenceVaultError("Recovery target already contains this evidence identifier.")
            self._connection.execute(
                """
                INSERT INTO evidence_vault_records
                    (institution_id, evidence_id, engagement_id, record_json, record_digest)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.institution_id,
                    record.evidence_id,
                    record.engagement_id,
                    canonical_json(record.as_dict()),
                    record.digest(),
                ),
            )
            for event in events:
                self._insert_event(event)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def verify(self, evidence_id: str) -> Mapping[str, Any]:
        record = self.load_record(evidence_id)
        events = self.load_events(evidence_id)
        state = verify_vault_history(record, events)
        return {
            "valid": True,
            "institution_id": self.institution_id,
            "engagement_id": record.engagement_id,
            "evidence_id": record.evidence_id,
            "record_digest": record.digest(),
            "custody_event_count": state.custody_event_count,
            "custody_head_hash": state.custody_head_hash,
            "retention_until": state.retention_until.isoformat(),
            "active_hold_ids": list(state.active_hold_ids),
            "encryption_envelope_present": True,
            "destructive_delete_supported": False,
        }

    def metadata(self) -> Mapping[str, Any]:
        row = self._connection.execute(
            "SELECT COUNT(*) AS count FROM evidence_vault_records WHERE institution_id = ?",
            (self.institution_id,),
        ).fetchone()
        return {
            "backend": "sqlite-reference-evidence-vault",
            "schema_version": _SCHEMA_VERSION,
            "institution_id": self.institution_id,
            "tenant_scope_enforced": True,
            "encryption_envelope_required": True,
            "application_api_append_only": True,
            "physical_worm_verified": False,
            "destructive_delete_supported": False,
            "record_count": int(row["count"]),
        }

    def _insert_event(self, event: VaultCustodyEvent) -> None:
        self._connection.execute(
            """
            INSERT INTO evidence_vault_events
                (institution_id, evidence_id, sequence, event_json, event_hash, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                self.institution_id,
                event.evidence_id,
                event.sequence,
                canonical_json(event.as_dict()),
                event.digest(),
                event.previous_hash,
            ),
        )

    def _assert_record(self, record: EvidenceVaultRecord) -> None:
        if record.institution_id != self.institution_id:
            raise EvidenceVaultError("Vault record belongs to another institution.")
