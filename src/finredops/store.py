"""Transactional SQLite persistence with tenant isolation and optional envelope encryption."""

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
from .crypto_provider import KmsHsmProvider
from .envelope import EnvelopeError, decrypt_json, encrypt_json, envelope_from_document
from .institution import InstitutionSecurityContext
from .models import canonical_json, ensure_aware, sha256_digest, to_primitive

_INSTITUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")


class PersistenceConflict(RuntimeError):
    """Raised when durable state diverges or protected content cannot be resolved safely."""


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
    """Institution-scoped durable store with opt-in KMS/HSM envelope protection.

    A handle is bound to exactly one institution.  When ``security_context`` and
    ``crypto_provider`` are supplied together, new snapshot and audit JSON payloads
    are encrypted with a fresh AES-256-GCM DEK per record.  The DEK is wrapped by
    the institution's active ``data_encryption`` key through the provider and only
    the envelope is persisted.  Hash/index metadata remains visible to SQLite so
    integrity and idempotency semantics continue to work without decrypting every
    row.
    """

    schema_version = 3

    def __init__(
        self,
        path: str | Path,
        *,
        institution_id: str = "default",
        security_context: InstitutionSecurityContext | None = None,
        crypto_provider: KmsHsmProvider | None = None,
    ) -> None:
        self.path = str(path)
        self.institution_id = _validate_institution_id(institution_id)
        if (security_context is None) != (crypto_provider is None):
            raise ValueError(
                "security_context and crypto_provider must be supplied together."
            )
        if security_context is not None:
            if security_context.institution_id != self.institution_id:
                raise ValueError("Security context belongs to a different institution.")
            data_key = security_context.active_key("data_encryption")
            if crypto_provider is None or crypto_provider.provider_name != data_key.provider:
                raise ValueError(
                    "Crypto provider does not match the institution data-encryption key."
                )
        self.security_context = security_context
        self.crypto_provider = crypto_provider
        self._encryption_enabled = security_context is not None and crypto_provider is not None
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

    def _create_v3_schema(self) -> None:
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
                protection_mode TEXT NOT NULL DEFAULT 'plaintext'
                    CHECK (protection_mode IN ('plaintext', 'envelope_v1')),
                protection_key_id TEXT,
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
                protection_mode TEXT NOT NULL DEFAULT 'plaintext'
                    CHECK (protection_mode IN ('plaintext', 'envelope_v1')),
                protection_key_id TEXT,
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
            PRAGMA user_version = 3;
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

    def _migrate_v2_to_v3(self) -> None:
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;
            ALTER TABLE engagement_snapshots
                ADD COLUMN protection_mode TEXT NOT NULL DEFAULT 'plaintext';
            ALTER TABLE engagement_snapshots
                ADD COLUMN protection_key_id TEXT;
            ALTER TABLE audit_events
                ADD COLUMN protection_mode TEXT NOT NULL DEFAULT 'plaintext';
            ALTER TABLE audit_events
                ADD COLUMN protection_key_id TEXT;
            PRAGMA user_version = 3;
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
            self._create_v3_schema()
            return
        if version == 1:
            self._migrate_v1_to_v2()
            version = 2
        if version == 2:
            self._migrate_v2_to_v3()

    def _protect_document(
        self,
        value: Any,
        *,
        object_type: str,
        object_id: str,
        now: datetime,
    ) -> tuple[str, str, str | None]:
        if not self._encryption_enabled:
            return canonical_json(value), "plaintext", None
        assert self.security_context is not None and self.crypto_provider is not None
        envelope = encrypt_json(
            value,
            institution_context=self.security_context,
            provider=self.crypto_provider,
            object_type=object_type,
            object_id=object_id,
            created_at=now,
        )
        return canonical_json(envelope.as_dict()), "envelope_v1", envelope.key_id

    def _unprotect_document(
        self,
        stored: str,
        *,
        protection_mode: str,
        object_type: str,
        object_id: str,
    ) -> Any:
        if protection_mode == "plaintext":
            return json.loads(stored)
        if protection_mode != "envelope_v1":
            raise PersistenceConflict("Unknown persisted protection mode.")
        if not self._encryption_enabled:
            raise PersistenceConflict(
                "Encrypted persisted content requires its institution security context and crypto provider."
            )
        assert self.security_context is not None and self.crypto_provider is not None
        try:
            envelope = envelope_from_document(json.loads(stored))
            if envelope.object_type != object_type or envelope.object_id != object_id:
                raise PersistenceConflict("Encrypted persisted object binding is invalid.")
            return decrypt_json(
                envelope,
                institution_context=self.security_context,
                provider=self.crypto_provider,
            )
        except (EnvelopeError, json.JSONDecodeError) as exc:
            if isinstance(exc, PersistenceConflict):
                raise
            raise PersistenceConflict("Encrypted persisted content failed authentication.") from exc

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
            protected, mode, key_id = self._protect_document(
                snapshot,
                object_type="snapshot",
                object_id=f"{engagement_id}:{revision}",
                now=now,
            )
            self._connection.execute(
                """
                INSERT INTO engagement_snapshots
                    (institution_id, engagement_id, revision, snapshot_json, snapshot_digest,
                     created_at, protection_mode, protection_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.institution_id,
                    engagement_id,
                    revision,
                    protected,
                    digest,
                    created_at,
                    mode,
                    key_id,
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
            SELECT revision, snapshot_json, protection_mode
            FROM engagement_snapshots
            WHERE institution_id = ? AND engagement_id = ?
            ORDER BY revision DESC LIMIT 1
            """,
            (self.institution_id, engagement_id),
        ).fetchone()
        if not row:
            return None
        value = self._unprotect_document(
            str(row["snapshot_json"]),
            protection_mode=str(row["protection_mode"]),
            object_type="snapshot",
            object_id=f"{engagement_id}:{int(row['revision'])}",
        )
        if not isinstance(value, dict):
            raise PersistenceConflict("Persisted snapshot plaintext is not a JSON object.")
        return value

    def list_engagements(self) -> tuple[dict[str, Any], ...]:
        rows = self._connection.execute(
            """
            SELECT s.engagement_id, s.revision, s.snapshot_digest, s.created_at,
                   s.protection_mode, s.protection_key_id
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
                SELECT sequence, event_json, protection_mode FROM audit_events
                WHERE institution_id = ? AND engagement_id = ? ORDER BY sequence
                """,
                (self.institution_id, engagement_id),
            ).fetchall()
            for index, row in enumerate(rows):
                sequence = int(row["sequence"])
                stored_value = self._unprotect_document(
                    str(row["event_json"]),
                    protection_mode=str(row["protection_mode"]),
                    object_type="audit_event",
                    object_id=f"{engagement_id}:{sequence}",
                )
                if index >= len(incoming) or canonical_json(stored_value) != incoming[index]:
                    raise PersistenceConflict(
                        "Persisted audit history is not an exact prefix of the incoming chain."
                    )
            for event in chain.events[len(rows) :]:
                protected, mode, key_id = self._protect_document(
                    to_primitive(event),
                    object_type="audit_event",
                    object_id=f"{engagement_id}:{event.sequence}",
                    now=event.timestamp,
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_events
                        (institution_id, engagement_id, sequence, event_json, event_hash,
                         previous_hash, protection_mode, protection_key_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.institution_id,
                        engagement_id,
                        event.sequence,
                        protected,
                        event.event_hash,
                        event.previous_hash,
                        mode,
                        key_id,
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
            SELECT sequence, event_json, protection_mode FROM audit_events
            WHERE institution_id = ? AND engagement_id = ? ORDER BY sequence
            """,
            (self.institution_id, engagement_id),
        ).fetchall()
        if not rows:
            return False, ("No persisted audit events exist for the engagement in this institution.",)
        try:
            documents = [
                canonical_json(
                    self._unprotect_document(
                        str(row["event_json"]),
                        protection_mode=str(row["protection_mode"]),
                        object_type="audit_event",
                        object_id=f"{engagement_id}:{int(row['sequence'])}",
                    )
                )
                for row in rows
            ]
        except PersistenceConflict as exc:
            return False, (str(exc),)
        chain = AuditChain.from_jsonl("\n".join(documents))
        valid, errors = chain.verify()
        if chain.events and chain.events[0].previous_hash != GENESIS_HASH:
            return False, (*errors, "Persisted audit chain does not begin at genesis.")
        if any(event.engagement_id != engagement_id for event in chain.events):
            return False, (*errors, "Persisted audit chain contains a different engagement id.")
        return valid and not errors, errors

    def encrypt_existing_records(self, *, now: datetime) -> dict[str, int]:
        """Rewrite legacy plaintext snapshot/audit JSON under the active institution KEK."""

        if not self._encryption_enabled:
            raise ValueError(
                "encrypt_existing_records requires an institution security context and crypto provider."
            )
        now = ensure_aware(now)
        snapshot_count = 0
        audit_count = 0
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            snapshots = self._connection.execute(
                """
                SELECT engagement_id, revision, snapshot_json
                FROM engagement_snapshots
                WHERE institution_id = ? AND protection_mode = 'plaintext'
                ORDER BY engagement_id, revision
                """,
                (self.institution_id,),
            ).fetchall()
            for row in snapshots:
                engagement_id = str(row["engagement_id"])
                revision = int(row["revision"])
                value = json.loads(str(row["snapshot_json"]))
                protected, mode, key_id = self._protect_document(
                    value,
                    object_type="snapshot",
                    object_id=f"{engagement_id}:{revision}",
                    now=now,
                )
                updated = self._connection.execute(
                    """
                    UPDATE engagement_snapshots
                    SET snapshot_json = ?, protection_mode = ?, protection_key_id = ?
                    WHERE institution_id = ? AND engagement_id = ? AND revision = ?
                      AND protection_mode = 'plaintext'
                    """,
                    (
                        protected,
                        mode,
                        key_id,
                        self.institution_id,
                        engagement_id,
                        revision,
                    ),
                ).rowcount
                if updated != 1:
                    raise PersistenceConflict("Snapshot changed during envelope migration.")
                snapshot_count += 1
            audits = self._connection.execute(
                """
                SELECT engagement_id, sequence, event_json
                FROM audit_events
                WHERE institution_id = ? AND protection_mode = 'plaintext'
                ORDER BY engagement_id, sequence
                """,
                (self.institution_id,),
            ).fetchall()
            for row in audits:
                engagement_id = str(row["engagement_id"])
                sequence = int(row["sequence"])
                value = json.loads(str(row["event_json"]))
                protected, mode, key_id = self._protect_document(
                    value,
                    object_type="audit_event",
                    object_id=f"{engagement_id}:{sequence}",
                    now=now,
                )
                updated = self._connection.execute(
                    """
                    UPDATE audit_events
                    SET event_json = ?, protection_mode = ?, protection_key_id = ?
                    WHERE institution_id = ? AND engagement_id = ? AND sequence = ?
                      AND protection_mode = 'plaintext'
                    """,
                    (
                        protected,
                        mode,
                        key_id,
                        self.institution_id,
                        engagement_id,
                        sequence,
                    ),
                ).rowcount
                if updated != 1:
                    raise PersistenceConflict("Audit event changed during envelope migration.")
                audit_count += 1
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return {"snapshots_encrypted": snapshot_count, "audit_events_encrypted": audit_count}

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

    def _protection_counts(self) -> tuple[int, int]:
        snapshot = self._connection.execute(
            """
            SELECT
              SUM(CASE WHEN protection_mode = 'envelope_v1' THEN 1 ELSE 0 END) encrypted,
              SUM(CASE WHEN protection_mode = 'plaintext' THEN 1 ELSE 0 END) plaintext
            FROM engagement_snapshots WHERE institution_id = ?
            """,
            (self.institution_id,),
        ).fetchone()
        audit = self._connection.execute(
            """
            SELECT
              SUM(CASE WHEN protection_mode = 'envelope_v1' THEN 1 ELSE 0 END) encrypted,
              SUM(CASE WHEN protection_mode = 'plaintext' THEN 1 ELSE 0 END) plaintext
            FROM audit_events WHERE institution_id = ?
            """,
            (self.institution_id,),
        ).fetchone()
        encrypted = int((snapshot["encrypted"] or 0) + (audit["encrypted"] or 0))
        plaintext = int((snapshot["plaintext"] or 0) + (audit["plaintext"] or 0))
        return encrypted, plaintext

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "SQLiteGovernanceStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def metadata(self) -> dict[str, Any]:
        encrypted, plaintext = self._protection_counts()
        return {
            "backend": "sqlite",
            "schema_version": self.schema_version,
            "path": self.path,
            "institution_id": self.institution_id,
            "tenant_scope_enforced": True,
            "envelope_encryption_configured": self._encryption_enabled,
            "encrypted_record_count": encrypted,
            "plaintext_legacy_record_count": plaintext,
            "encryption_at_rest_verified": bool(
                self._encryption_enabled and encrypted > 0 and plaintext == 0
            ),
            "active_data_key_id": (
                self.security_context.active_key("data_encryption").key_id
                if self.security_context is not None
                else None
            ),
            "engagements": [to_primitive(item) for item in self.list_engagements()],
        }
