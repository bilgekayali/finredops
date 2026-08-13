"""Shared validation contracts for the evidence vault lifecycle."""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from .models import StringEnum

MAX_EVIDENCE_BYTES = 20_000_000
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
