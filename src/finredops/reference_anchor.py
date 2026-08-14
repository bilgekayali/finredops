"""Reference append-only anchor authority for separate-service deployments and tests.

This module is service-side. Production clients should not receive the anchor
private key; they retain only signed receipts plus the public trust bundle.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .anchor_models import AuditAnchorCommitment, AuditAnchorReceipt, b64url, receipt_from_document
from .models import canonical_json

_SCHEMA_VERSION = 1


def _digest_bytes(document: dict[str, object]) -> tuple[str, bytes]:
    value = hashlib.sha256(canonical_json(document).encode("utf-8")).digest()
    return value.hex(), value


class ReferenceAppendOnlyAnchorAuthority:
    """Signed append-only ledger intended to run outside the FinRedOps database boundary."""

    def __init__(
        self,
        path: Path,
        *,
        anchor_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.anchor_id = anchor_id
        self.key_id = key_id
        self._private_key = private_key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise RuntimeError(
                    f"Unsupported reference anchor SQLite schema version {version}."
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS anchor_receipts (
                    sequence INTEGER PRIMARY KEY,
                    anchor_id TEXT NOT NULL,
                    institution_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    commitment_digest TEXT NOT NULL UNIQUE,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                )
                """
            )
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        if self.path.exists() and os.name == "posix":
            os.chmod(self.path, 0o600)

    def append(self, commitment: AuditAnchorCommitment) -> AuditAnchorReceipt:
        digest = commitment.digest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT document_json FROM anchor_receipts WHERE commitment_digest = ?",
                (digest,),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return receipt_from_document(json.loads(existing["document_json"]))
            last = connection.execute(
                "SELECT sequence, receipt_digest, document_json FROM anchor_receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if last is None else int(last["sequence"]) + 1
            previous = "0" * 64 if last is None else str(last["receipt_digest"])
            anchored_at = self._clock()
            if anchored_at.tzinfo is None or anchored_at.utcoffset() is None:
                raise ValueError("Anchor clock must return a timezone-aware timestamp.")
            if last is not None:
                last_receipt = receipt_from_document(json.loads(last["document_json"]))
                if anchored_at < last_receipt.anchored_at:
                    raise ValueError("Anchor clock cannot move backwards across appended receipts.")
            draft = AuditAnchorReceipt(
                anchor_id=self.anchor_id,
                sequence=sequence,
                institution_id=commitment.institution_id,
                engagement_id=commitment.engagement_id,
                commitment_digest=digest,
                previous_receipt_digest=previous,
                anchored_at=anchored_at,
                key_id=self.key_id,
                signature_algorithm="Ed25519-SHA256-DIGEST",
                signature=b64url(b"placeholder"),
                signing_document_digest="0" * 64,
            )
            signing_hex, signing_digest = _digest_bytes(draft.signing_document())
            signature = b64url(self._private_key.sign(signing_digest))
            receipt = AuditAnchorReceipt(
                anchor_id=self.anchor_id,
                sequence=sequence,
                institution_id=commitment.institution_id,
                engagement_id=commitment.engagement_id,
                commitment_digest=digest,
                previous_receipt_digest=previous,
                anchored_at=anchored_at,
                key_id=self.key_id,
                signature_algorithm="Ed25519-SHA256-DIGEST",
                signature=signature,
                signing_document_digest=signing_hex,
            )
            receipt = AuditAnchorReceipt(**receipt.core(), receipt_digest=receipt.digest())
            connection.execute(
                "INSERT INTO anchor_receipts(sequence, anchor_id, institution_id, engagement_id, commitment_digest, receipt_digest, document_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt.sequence,
                    receipt.anchor_id,
                    receipt.institution_id,
                    receipt.engagement_id,
                    receipt.commitment_digest,
                    receipt.digest(),
                    canonical_json(receipt.as_dict()),
                ),
            )
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def receipts(self) -> tuple[AuditAnchorReceipt, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT document_json FROM anchor_receipts ORDER BY sequence"
            ).fetchall()
        return tuple(receipt_from_document(json.loads(row["document_json"])) for row in rows)
