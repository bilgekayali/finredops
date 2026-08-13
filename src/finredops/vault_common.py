"""Shared contracts for the institution-scoped encrypted evidence vault."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import date, datetime
from typing import Any, Mapping

from .envelope import EnvelopeEncryptedArtifact, envelope_from_document
from .models import (
    DataClassification,
    StringEnum,
    ensure_aware,
    parse_datetime,
    sha256_digest,
    to_primitive,
)

MAX_EVIDENCE_BYTES = 20_000_000
RECORD_SCHEMA = "finredops.evidence-vault-record.v1"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,127}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")


class EvidenceVaultError(ValueError):
    """Raised when evidence-vault data or lifecycle state is invalid."""


class VaultCustodyAction(StringEnum):
    INGESTED = "ingested"
    ACCESSED = "accessed"
    EXPORTED = "exported"
    LEGAL_HOLD_APPLIED = "legal_hold_applied"
    LEGAL_HOLD_RELEASED = "legal_hold_released"
    RETENTION_EXTENDED = "retention_extended"
    DELETION_APPROVED = "deletion_approved"
    RESTORED = "restored"


def bounded_text(value: Any, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise EvidenceVaultError(f"{name} must be bounded non-empty text.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvidenceVaultError(f"{name} contains control characters.")
    return value


def identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EvidenceVaultError(f"{name} must be a bounded safe identifier.")
    return value


def digest_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise EvidenceVaultError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def media_type(value: Any) -> str:
    if not isinstance(value, str) or not _MEDIA_TYPE.fullmatch(value):
        raise EvidenceVaultError("media_type must be a normalized MIME type.")
    return value


def retention_date(value: Any, name: str = "retention_until") -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise EvidenceVaultError(f"{name} must use YYYY-MM-DD format.") from exc
    raise EvidenceVaultError(f"{name} must be a date or YYYY-MM-DD string.")


@dataclass(frozen=True, slots=True)
class EvidenceVaultRecord:
    institution_id: str
    engagement_id: str
    evidence_id: str
    title: str
    classification: DataClassification
    media_type: str
    size_bytes: int
    content_sha256: str
    source_system: str
    collected_by: str
    collected_at: datetime
    ingested_at: datetime
    retention_until: date
    envelope: EnvelopeEncryptedArtifact
    record_digest: str = ""
    schema_version: str = RECORD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECORD_SCHEMA:
            raise EvidenceVaultError("Unsupported evidence-vault record schema.")
        identifier(self.institution_id, "institution_id")
        identifier(self.engagement_id, "engagement_id")
        identifier(self.evidence_id, "evidence_id")
        bounded_text(self.title, "title")
        bounded_text(self.source_system, "source_system")
        bounded_text(self.collected_by, "collected_by")
        if not isinstance(self.classification, DataClassification):
            raise EvidenceVaultError("classification must be a DataClassification value.")
        media_type(self.media_type)
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise EvidenceVaultError("size_bytes must be an integer.")
        if not 0 <= self.size_bytes <= MAX_EVIDENCE_BYTES:
            raise EvidenceVaultError("Evidence exceeds the bounded 20 MB reference-vault limit.")
        digest_text(self.content_sha256, "content_sha256")
        if not isinstance(self.envelope, EnvelopeEncryptedArtifact):
            raise EvidenceVaultError("Evidence envelope must be a verified envelope artifact.")
        collected_at = ensure_aware(self.collected_at)
        ingested_at = ensure_aware(self.ingested_at)
        retention_until = retention_date(self.retention_until)
        if ingested_at < collected_at:
            raise EvidenceVaultError("Evidence cannot be ingested before collection.")
        if retention_until < collected_at.date():
            raise EvidenceVaultError("Retention cannot end before collection.")
        if self.envelope.institution_id != self.institution_id:
            raise EvidenceVaultError("Evidence envelope belongs to another institution.")
        if self.envelope.object_type != "evidence_vault":
            raise EvidenceVaultError("Evidence envelope object type is invalid.")
        if self.envelope.object_id != f"{self.engagement_id}:{self.evidence_id}":
            raise EvidenceVaultError("Evidence envelope object identity is invalid.")
        if self.envelope.plaintext_digest != self.content_sha256:
            raise EvidenceVaultError("Evidence content digest does not match its envelope.")
        object.__setattr__(self, "collected_at", collected_at)
        object.__setattr__(self, "ingested_at", ingested_at)
        object.__setattr__(self, "retention_until", retention_until)
        if self.record_digest:
            digest_text(self.record_digest, "record_digest")
            if self.record_digest != self.digest():
                raise EvidenceVaultError("Evidence-vault record digest mismatch.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "engagement_id": self.engagement_id,
            "evidence_id": self.evidence_id,
            "title": self.title,
            "classification": self.classification.value,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "source_system": self.source_system,
            "collected_by": self.collected_by,
            "collected_at": self.collected_at,
            "ingested_at": self.ingested_at,
            "retention_until": self.retention_until.isoformat(),
            "envelope": self.envelope.as_dict(),
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def sealed(self) -> "EvidenceVaultRecord":
        return replace(self, record_digest=self.digest())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "record_digest": self.digest()}


def vault_record_from_document(document: Any) -> EvidenceVaultRecord:
    fields = {
        "schema_version", "institution_id", "engagement_id", "evidence_id", "title",
        "classification", "media_type", "size_bytes", "content_sha256", "source_system",
        "collected_by", "collected_at", "ingested_at", "retention_until", "envelope",
        "record_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EvidenceVaultError("Vault record does not match the strict v1 contract.")
    try:
        return EvidenceVaultRecord(
            institution_id=document["institution_id"],
            engagement_id=document["engagement_id"],
            evidence_id=document["evidence_id"],
            title=document["title"],
            classification=DataClassification(document["classification"]),
            media_type=document["media_type"],
            size_bytes=document["size_bytes"],
            content_sha256=document["content_sha256"],
            source_system=document["source_system"],
            collected_by=document["collected_by"],
            collected_at=parse_datetime(document["collected_at"]),
            ingested_at=parse_datetime(document["ingested_at"]),
            retention_until=retention_date(document["retention_until"]),
            envelope=envelope_from_document(document["envelope"]),
            record_digest=document["record_digest"],
            schema_version=document["schema_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceVaultError):
            raise
        raise EvidenceVaultError(f"Invalid vault record: {exc}") from exc
