"""Append-only custody, hold, retention and deletion-eligibility state."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
from typing import Any, Mapping, Sequence

from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .vault_common import (
    EvidenceVaultError,
    EvidenceVaultRecord,
    VaultCustodyAction,
    bounded_text,
    digest_text,
    identifier,
    retention_date,
)

EVENT_SCHEMA = "finredops.evidence-vault-custody-event.v1"
ELIGIBILITY_SCHEMA = "finredops.evidence-vault-deletion-eligibility.v1"


@dataclass(frozen=True, slots=True)
class VaultCustodyEvent:
    institution_id: str
    engagement_id: str
    evidence_id: str
    sequence: int
    timestamp: datetime
    actor_id: str
    action: VaultCustodyAction
    purpose: str
    details: Mapping[str, Any]
    previous_hash: str
    event_hash: str = ""
    schema_version: str = EVENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != EVENT_SCHEMA:
            raise EvidenceVaultError("Unsupported vault custody-event schema.")
        identifier(self.institution_id, "institution_id")
        identifier(self.engagement_id, "engagement_id")
        identifier(self.evidence_id, "evidence_id")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise EvidenceVaultError("Custody sequence must be a positive integer.")
        bounded_text(self.actor_id, "actor_id", maximum=256)
        bounded_text(self.purpose, "purpose", maximum=1000)
        if not isinstance(self.action, VaultCustodyAction):
            raise EvidenceVaultError("Unknown vault custody action.")
        if not isinstance(self.details, Mapping):
            raise EvidenceVaultError("Custody details must be an object.")
        object.__setattr__(self, "details", dict(self.details))
        object.__setattr__(self, "timestamp", ensure_aware(self.timestamp))
        if self.sequence == 1:
            if self.previous_hash != "0" * 64:
                raise EvidenceVaultError("First custody event must use the zero previous hash.")
        else:
            digest_text(self.previous_hash, "previous_hash")
        if self.event_hash:
            digest_text(self.event_hash, "event_hash")
            if self.event_hash != self.digest():
                raise EvidenceVaultError("Custody event hash mismatch.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "engagement_id": self.engagement_id,
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "actor_id": self.actor_id,
            "action": self.action.value,
            "purpose": self.purpose,
            "details": dict(self.details),
            "previous_hash": self.previous_hash,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def sealed(self) -> "VaultCustodyEvent":
        return replace(self, event_hash=self.digest())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "event_hash": self.digest()}


@dataclass(frozen=True, slots=True)
class EvidenceVaultState:
    institution_id: str
    engagement_id: str
    evidence_id: str
    retention_until: date
    active_hold_ids: tuple[str, ...]
    custody_event_count: int
    custody_head_hash: str
    record_digest: str
    latest_deletion_approval_digest: str | None

    def digest(self) -> str:
        return sha256_digest(
            {
                "institution_id": self.institution_id,
                "engagement_id": self.engagement_id,
                "evidence_id": self.evidence_id,
                "retention_until": self.retention_until.isoformat(),
                "active_hold_ids": self.active_hold_ids,
                "custody_event_count": self.custody_event_count,
                "custody_head_hash": self.custody_head_hash,
                "record_digest": self.record_digest,
                "latest_deletion_approval_digest": self.latest_deletion_approval_digest,
            }
        )


@dataclass(frozen=True, slots=True)
class DeletionEligibility:
    institution_id: str
    engagement_id: str
    evidence_id: str
    evaluated_at: datetime
    retention_until: date
    active_hold_ids: tuple[str, ...]
    record_digest: str
    custody_head_hash: str
    state_digest: str
    eligible: bool
    reasons: tuple[str, ...]
    eligibility_digest: str = ""
    schema_version: str = ELIGIBILITY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ELIGIBILITY_SCHEMA:
            raise EvidenceVaultError("Unsupported deletion-eligibility schema.")
        object.__setattr__(self, "evaluated_at", ensure_aware(self.evaluated_at))
        object.__setattr__(self, "retention_until", retention_date(self.retention_until))
        object.__setattr__(self, "active_hold_ids", tuple(self.active_hold_ids))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        for hold_id in self.active_hold_ids:
            identifier(hold_id, "active hold id")
        for reason in self.reasons:
            bounded_text(reason, "eligibility reason", maximum=128)
        digest_text(self.record_digest, "record_digest")
        digest_text(self.custody_head_hash, "custody_head_hash")
        digest_text(self.state_digest, "state_digest")
        if self.eligible != (not self.reasons):
            raise EvidenceVaultError("Eligibility flag and reasons disagree.")
        if self.eligibility_digest:
            digest_text(self.eligibility_digest, "eligibility_digest")
            if self.eligibility_digest != self.digest():
                raise EvidenceVaultError("Deletion eligibility digest mismatch.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "engagement_id": self.engagement_id,
            "evidence_id": self.evidence_id,
            "evaluated_at": self.evaluated_at,
            "retention_until": self.retention_until.isoformat(),
            "active_hold_ids": self.active_hold_ids,
            "record_digest": self.record_digest,
            "custody_head_hash": self.custody_head_hash,
            "state_digest": self.state_digest,
            "eligible": self.eligible,
            "reasons": self.reasons,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def sealed(self) -> "DeletionEligibility":
        return replace(self, eligibility_digest=self.digest())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "eligibility_digest": self.digest()}


def new_custody_event(
    record: EvidenceVaultRecord,
    events: Sequence[VaultCustodyEvent],
    *,
    action: VaultCustodyAction,
    actor_id: str,
    purpose: str,
    now: datetime,
    details: Mapping[str, Any] | None = None,
) -> VaultCustodyEvent:
    previous = events[-1].digest() if events else "0" * 64
    return VaultCustodyEvent(
        institution_id=record.institution_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        sequence=len(events) + 1,
        timestamp=ensure_aware(now),
        actor_id=actor_id,
        action=action,
        purpose=purpose,
        details=dict(details or {}),
        previous_hash=previous,
    ).sealed()


def evaluate_deletion_eligibility(
    record: EvidenceVaultRecord,
    state: EvidenceVaultState,
    *,
    now: datetime,
) -> DeletionEligibility:
    now = ensure_aware(now)
    if state.record_digest != record.digest():
        raise EvidenceVaultError("Vault state is not bound to the current record.")
    reasons: list[str] = []
    if now.date() < state.retention_until:
        reasons.append("retention_active")
    if state.active_hold_ids:
        reasons.append("legal_hold_active")
    return DeletionEligibility(
        institution_id=record.institution_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        evaluated_at=now,
        retention_until=state.retention_until,
        active_hold_ids=state.active_hold_ids,
        record_digest=record.digest(),
        custody_head_hash=state.custody_head_hash,
        state_digest=state.digest(),
        eligible=not reasons,
        reasons=tuple(reasons),
    ).sealed()


def custody_event_from_document(document: Any) -> VaultCustodyEvent:
    fields = {
        "schema_version", "institution_id", "engagement_id", "evidence_id", "sequence",
        "timestamp", "actor_id", "action", "purpose", "details", "previous_hash", "event_hash",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EvidenceVaultError("Vault custody event does not match the strict v1 contract.")
    try:
        return VaultCustodyEvent(
            institution_id=document["institution_id"],
            engagement_id=document["engagement_id"],
            evidence_id=document["evidence_id"],
            sequence=document["sequence"],
            timestamp=parse_datetime(document["timestamp"]),
            actor_id=document["actor_id"],
            action=VaultCustodyAction(document["action"]),
            purpose=document["purpose"],
            details=document["details"],
            previous_hash=document["previous_hash"],
            event_hash=document["event_hash"],
            schema_version=document["schema_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceVaultError):
            raise
        raise EvidenceVaultError(f"Invalid vault custody event: {exc}") from exc


def deletion_eligibility_from_document(document: Any) -> DeletionEligibility:
    fields = {
        "schema_version", "institution_id", "engagement_id", "evidence_id", "evaluated_at",
        "retention_until", "active_hold_ids", "record_digest", "custody_head_hash",
        "state_digest", "eligible", "reasons", "eligibility_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EvidenceVaultError("Deletion eligibility does not match the strict v1 contract.")
    if not isinstance(document["eligible"], bool):
        raise EvidenceVaultError("Deletion eligibility flag must be Boolean.")
    if not isinstance(document["active_hold_ids"], list) or not isinstance(document["reasons"], list):
        raise EvidenceVaultError("Deletion eligibility arrays are invalid.")
    return DeletionEligibility(
        institution_id=document["institution_id"],
        engagement_id=document["engagement_id"],
        evidence_id=document["evidence_id"],
        evaluated_at=parse_datetime(document["evaluated_at"]),
        retention_until=retention_date(document["retention_until"]),
        active_hold_ids=tuple(document["active_hold_ids"]),
        record_digest=document["record_digest"],
        custody_head_hash=document["custody_head_hash"],
        state_digest=document["state_digest"],
        eligible=document["eligible"],
        reasons=tuple(document["reasons"]),
        eligibility_digest=document["eligibility_digest"],
        schema_version=document["schema_version"],
    )
