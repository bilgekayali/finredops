"""Portable encrypted evidence recovery bundle."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Mapping

from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .vault_common import EvidenceVaultError, EvidenceVaultRecord, bounded_text, digest_text
from .vault_custody import VaultCustodyEvent, custody_event_from_document
from .vault_history import verify_vault_history

RECOVERY_SCHEMA = "finredops.evidence-vault-recovery-bundle.v1"


@dataclass(frozen=True, slots=True)
class EvidenceVaultRecoveryBundle:
    record: EvidenceVaultRecord
    custody_events: tuple[VaultCustodyEvent, ...]
    exported_at: datetime
    exported_by: str
    purpose: str
    bundle_digest: str = ""
    schema_version: str = RECOVERY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECOVERY_SCHEMA:
            raise EvidenceVaultError("Unsupported recovery-bundle schema.")
        if not isinstance(self.record, EvidenceVaultRecord):
            raise EvidenceVaultError("Recovery record must be a verified vault record.")
        object.__setattr__(self, "custody_events", tuple(self.custody_events))
        if any(not isinstance(event, VaultCustodyEvent) for event in self.custody_events):
            raise EvidenceVaultError("Recovery custody history contains an invalid event.")
        object.__setattr__(self, "exported_at", ensure_aware(self.exported_at))
        bounded_text(self.exported_by, "exported_by", maximum=256)
        bounded_text(self.purpose, "purpose", maximum=1000)
        verify_vault_history(self.record, self.custody_events)
        if self.bundle_digest:
            digest_text(self.bundle_digest, "bundle_digest")
            if self.bundle_digest != self.digest():
                raise EvidenceVaultError("Recovery bundle digest mismatch.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record": self.record.as_dict(),
            "custody_events": [event.as_dict() for event in self.custody_events],
            "exported_at": self.exported_at,
            "exported_by": self.exported_by,
            "purpose": self.purpose,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def sealed(self) -> "EvidenceVaultRecoveryBundle":
        return replace(self, bundle_digest=self.digest())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "bundle_digest": self.digest()}


def recovery_bundle_from_document(document: Any) -> EvidenceVaultRecoveryBundle:
    fields = {
        "schema_version",
        "record",
        "custody_events",
        "exported_at",
        "exported_by",
        "purpose",
        "bundle_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EvidenceVaultError("Recovery bundle does not match the strict v1 contract.")
    if not isinstance(document["custody_events"], list):
        raise EvidenceVaultError("Recovery custody_events must be an array.")
    from .vault_common import vault_record_from_document

    return EvidenceVaultRecoveryBundle(
        record=vault_record_from_document(document["record"]),
        custody_events=tuple(custody_event_from_document(item) for item in document["custody_events"]),
        exported_at=parse_datetime(document["exported_at"]),
        exported_by=document["exported_by"],
        purpose=document["purpose"],
        bundle_digest=document["bundle_digest"],
        schema_version=document["schema_version"],
    )
