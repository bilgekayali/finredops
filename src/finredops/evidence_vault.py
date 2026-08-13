"""Institution-scoped encrypted evidence-vault lifecycle.

The vault core deliberately separates retention/legal-hold/deletion approval from
physical destruction. Raw evidence is always represented by an institution-bound
envelope artifact; the core never stores plaintext outside the immediate crypto
operation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .crypto_provider import KmsHsmProvider
from .envelope import (
    EnvelopeEncryptedArtifact,
    decrypt_bytes,
    encrypt_bytes,
    envelope_from_document,
)
from .institution import InstitutionSecurityContext
from .models import DataClassification, StringEnum, ensure_aware, parse_datetime, sha256_digest, to_primitive

_RECORD_SCHEMA = "finredops.evidence-vault-record.v1"
_EVENT_SCHEMA = "finredops.evidence-vault-custody-event.v1"
_ELIGIBILITY_SCHEMA = "finredops.evidence-vault-deletion-eligibility.v1"
_RECOVERY_SCHEMA = "finredops.evidence-vault-recovery-bundle.v1"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,127}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_MAX_EVIDENCE_BYTES = 20_000_000


class EvidenceVaultError(ValueError):
    """Raised when evidence-vault state or custody semantics are invalid."""


class VaultCustodyAction(StringEnum):
    INGESTED = "ingested"
    ACCESSED = "accessed"
    EXPORTED = "exported"
    LEGAL_HOLD_APPLIED = "legal_hold_applied"
    LEGAL_HOLD_RELEASED = "legal_hold_released"
    RETENTION_EXTENDED = "retention_extended"
    DELETION_APPROVED = "deletion_approved"
    RESTORED = "restored"


def _bounded(value: Any, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise EvidenceVaultError(f"{name} must be bounded non-empty text.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise EvidenceVaultError(f"{name} contains control characters.")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EvidenceVaultError(f"{name} must be a bounded safe identifier.")
    return value


def _date(value: Any, name: str) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise EvidenceVaultError(f"{name} must use YYYY-MM-DD format.") from exc
    raise EvidenceVaultError(f"{name} must be a date or YYYY-MM-DD string.")


def _digest(value: str, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise EvidenceVaultError(f"{name} must be a lowercase SHA-256 digest.")
    return value


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
    schema_version: str = _RECORD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _RECORD_SCHEMA:
            raise EvidenceVaultError("Unsupported evidence-vault record schema.")
        _identifier(self.institution_id, "institution_id")
        _identifier(self.engagement_id, "engagement_id")
        _identifier(self.evidence_id, "evidence_id")
        _bounded(self.title, "title")
        _bounded(self.source_system, "source_system")
        _bounded(self.collected_by, "collected_by")
        if not isinstance(self.classification, DataClassification):
            raise EvidenceVaultError("classification must be a DataClassification value.")
        if not isinstance(self.media_type, str) or not _MEDIA_TYPE.fullmatch(self.media_type):
            raise EvidenceVaultError("media_type must be a normalized MIME type.")
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise EvidenceVaultError("size_bytes must be an integer.")
        if not 0 <= self.size_bytes <= _MAX_EVIDENCE_BYTES:
            raise EvidenceVaultError("Evidence exceeds the bounded 20 MB reference-vault limit.")
        _digest(self.content_sha256, "content_sha256")
        collected_at = ensure_aware(self.collected_at)
        ingested_at = ensure_aware(self.ingested_at)
        retention_until = _date(self.retention_until, "retention_until")
        if ingested_at < collected_at:
            raise EvidenceVaultError("Evidence cannot be ingested before collection.")
        if retention_until < collected_at.date():
            raise EvidenceVaultError("Retention cannot end before collection.")
        expected_object_id = f"{self.engagement_id}:{self.evidence_id}"
        if self.envelope.institution_id != self.institution_id:
            raise EvidenceVaultError("Evidence envelope belongs to another institution.")
        if self.envelope.object_type != "evidence_vault" or self.envelope.object_id != expected_object_id:
            raise EvidenceVaultError("Evidence envelope object binding is invalid.")
        if self.envelope.plaintext_digest != self.content_sha256:
            raise EvidenceVaultError("Evidence content digest does not match the encrypted envelope.")
        object.__setattr__(self, "collected_at", collected_at)
        object.__setattr__(self, "ingested_at", ingested_at)
        object.__setattr__(self, "retention_until", retention_until)
        if self.record_digest:
            _digest(self.record_digest, "record_digest")
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

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "record_digest": self.digest()}


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
    schema_version: str = _EVENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _EVENT_SCHEMA:
            raise EvidenceVaultError("Unsupported vault custody-event schema.")
        _identifier(self.institution_id, "institution_id")
        _identifier(self.engagement_id, "engagement_id")
        _identifier(self.evidence_id, "evidence_id")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise EvidenceVaultError("Custody sequence must be a positive integer.")
        _bounded(self.actor_id, "actor_id", maximum=256)
        _bounded(self.purpose, "purpose", maximum=1000)
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
            _digest(self.previous_hash, "previous_hash")
        if self.event_hash:
            _digest(self.event_hash, "event_hash")
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
    schema_version: str = _ELIGIBILITY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _ELIGIBILITY_SCHEMA:
            raise EvidenceVaultError("Unsupported deletion-eligibility schema.")
        object.__setattr__(self, "evaluated_at", ensure_aware(self.evaluated_at))
        object.__setattr__(self, "retention_until", _date(self.retention_until, "retention_until"))
        object.__setattr__(self, "active_hold_ids", tuple(self.active_hold_ids))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        _digest(self.record_digest, "record_digest")
        _digest(self.custody_head_hash, "custody_head_hash")
        _digest(self.state_digest, "state_digest")
        if self.eligible != (not self.reasons):
            raise EvidenceVaultError("Eligibility flag and reasons disagree.")
        if self.eligibility_digest:
            _digest(self.eligibility_digest, "eligibility_digest")
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

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "eligibility_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class EvidenceVaultRecoveryBundle:
    record: EvidenceVaultRecord
    custody_events: tuple[VaultCustodyEvent, ...]
    exported_at: datetime
    exported_by: str
    purpose: str
    bundle_digest: str = ""
    schema_version: str = _RECOVERY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _RECOVERY_SCHEMA:
            raise EvidenceVaultError("Unsupported recovery-bundle schema.")
        object.__setattr__(self, "custody_events", tuple(self.custody_events))
        object.__setattr__(self, "exported_at", ensure_aware(self.exported_at))
        _bounded(self.exported_by, "exported_by", maximum=256)
        _bounded(self.purpose, "purpose", maximum=1000)
        verify_vault_history(self.record, self.custody_events)
        if self.bundle_digest:
            _digest(self.bundle_digest, "bundle_digest")
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

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "bundle_digest": self.digest()}


@runtime_checkable
class EvidenceVaultBackend(Protocol):
    """Persistence boundary for encrypted vault records and append-only custody."""

    institution_id: str

    def create(self, record: EvidenceVaultRecord, initial_event: VaultCustodyEvent) -> None: ...
    def load_record(self, evidence_id: str) -> EvidenceVaultRecord: ...
    def load_events(self, evidence_id: str) -> tuple[VaultCustodyEvent, ...]: ...
    def append_event(self, event: VaultCustodyEvent) -> None: ...
    def restore(self, record: EvidenceVaultRecord, events: Sequence[VaultCustodyEvent]) -> None: ...
    def metadata(self) -> Mapping[str, Any]: ...


def _new_event(
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
    event = VaultCustodyEvent(
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
    )
    return VaultCustodyEvent(**event.core(), event_hash=event.digest())


def verify_vault_history(
    record: EvidenceVaultRecord,
    events: Sequence[VaultCustodyEvent],
) -> EvidenceVaultState:
    events = tuple(events)
    if not events:
        raise EvidenceVaultError("Evidence vault record has no custody history.")
    retention_until = record.retention_until
    active_holds: set[str] = set()
    seen_holds: set[str] = set()
    latest_deletion: str | None = None
    previous = "0" * 64
    for index, event in enumerate(events, start=1):
        if event.sequence != index:
            raise EvidenceVaultError("Custody sequence is not contiguous.")
        if (
            event.institution_id != record.institution_id
            or event.engagement_id != record.engagement_id
            or event.evidence_id != record.evidence_id
        ):
            raise EvidenceVaultError("Custody event crosses the evidence tenant/object boundary.")
        if event.previous_hash != previous:
            raise EvidenceVaultError("Custody previous-hash continuity is invalid.")
        if event.event_hash and event.event_hash != event.digest():
            raise EvidenceVaultError("Custody event hash is invalid.")
        if event.timestamp < record.collected_at:
            raise EvidenceVaultError("Custody activity predates evidence collection.")
        details = dict(event.details)
        if index == 1:
            if event.action != VaultCustodyAction.INGESTED:
                raise EvidenceVaultError("Evidence custody must begin with ingest.")
            if details != {
                "record_digest": record.digest(),
                "envelope_digest": record.envelope.digest(),
            }:
                raise EvidenceVaultError("Ingest event is not bound to the vault record and envelope.")
        elif event.action == VaultCustodyAction.INGESTED:
            raise EvidenceVaultError("Evidence can have only one ingest event.")
        elif event.action == VaultCustodyAction.LEGAL_HOLD_APPLIED:
            hold_id = _identifier(details.get("hold_id"), "hold_id")
            _bounded(details.get("reason"), "hold reason", maximum=1000)
            if hold_id in seen_holds:
                raise EvidenceVaultError("Legal-hold identifier cannot be reused.")
            seen_holds.add(hold_id)
            active_holds.add(hold_id)
        elif event.action == VaultCustodyAction.LEGAL_HOLD_RELEASED:
            hold_id = _identifier(details.get("hold_id"), "hold_id")
            _bounded(details.get("reason"), "hold release reason", maximum=1000)
            if hold_id not in active_holds:
                raise EvidenceVaultError("Only an active legal hold can be released.")
            active_holds.remove(hold_id)
        elif event.action == VaultCustodyAction.RETENTION_EXTENDED:
            new_until = _date(details.get("retention_until"), "retention_until")
            if new_until <= retention_until:
                raise EvidenceVaultError("Retention may only be extended, never shortened.")
            retention_until = new_until
        elif event.action == VaultCustodyAction.DELETION_APPROVED:
            eligibility = deletion_eligibility_from_document(details.get("eligibility"))
            state_before = EvidenceVaultState(
                institution_id=record.institution_id,
                engagement_id=record.engagement_id,
                evidence_id=record.evidence_id,
                retention_until=retention_until,
                active_hold_ids=tuple(sorted(active_holds)),
                custody_event_count=index - 1,
                custody_head_hash=previous,
                record_digest=record.digest(),
                latest_deletion_approval_digest=latest_deletion,
            )
            expected = evaluate_deletion_eligibility(record, state_before, now=event.timestamp)
            if eligibility.as_dict() != expected.as_dict() or not eligibility.eligible:
                raise EvidenceVaultError("Deletion approval is not bound to current eligible state.")
            latest_deletion = eligibility.digest()
        elif event.action == VaultCustodyAction.RESTORED:
            _digest(str(details.get("recovery_bundle_digest", "")), "recovery_bundle_digest")
        elif event.action == VaultCustodyAction.EXPORTED:
            _bounded(details.get("recipient"), "export recipient", maximum=512)
        elif event.action == VaultCustodyAction.ACCESSED:
            if details:
                raise EvidenceVaultError("Access custody event must not embed evidence data.")
        previous = event.digest()
    return EvidenceVaultState(
        institution_id=record.institution_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        retention_until=retention_until,
        active_hold_ids=tuple(sorted(active_holds)),
        custody_event_count=len(events),
        custody_head_hash=previous,
        record_digest=record.digest(),
        latest_deletion_approval_digest=latest_deletion,
    )


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
    result = DeletionEligibility(
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
    )
    return DeletionEligibility(**result.core(), eligibility_digest=result.digest())


class EvidenceVault:
    """Institution-bound evidence lifecycle service over an append-only backend."""

    def __init__(
        self,
        *,
        institution_context: InstitutionSecurityContext,
        provider: KmsHsmProvider,
        backend: EvidenceVaultBackend,
    ) -> None:
        if backend.institution_id != institution_context.institution_id:
            raise EvidenceVaultError("Vault backend and institution context do not match.")
        if provider.provider_name != institution_context.active_key("data_encryption").provider:
            raise EvidenceVaultError("Vault crypto provider does not match active institution encryption key.")
        self.institution_context = institution_context
        self.provider = provider
        self.backend = backend

    @property
    def institution_id(self) -> str:
        return self.institution_context.institution_id

    def ingest(
        self,
        content: bytes,
        *,
        engagement_id: str,
        evidence_id: str,
        title: str,
        classification: DataClassification,
        media_type: str,
        source_system: str,
        collected_by: str,
        collected_at: datetime,
        retention_until: date,
        actor_id: str,
        now: datetime,
        purpose: str = "Ingest encrypted evidence into the institution vault.",
    ) -> EvidenceVaultRecord:
        if not isinstance(content, bytes):
            raise EvidenceVaultError("Evidence content must be bytes.")
        engagement_id = _identifier(engagement_id, "engagement_id")
        evidence_id = _identifier(evidence_id, "evidence_id")
        now = ensure_aware(now)
        envelope = encrypt_bytes(
            content,
            institution_context=self.institution_context,
            provider=self.provider,
            object_type="evidence_vault",
            object_id=f"{engagement_id}:{evidence_id}",
            created_at=now,
        )
        record = EvidenceVaultRecord(
            institution_id=self.institution_id,
            engagement_id=engagement_id,
            evidence_id=evidence_id,
            title=title,
            classification=classification,
            media_type=media_type,
            size_bytes=len(content),
            content_sha256=envelope.plaintext_digest,
            source_system=source_system,
            collected_by=collected_by,
            collected_at=collected_at,
            ingested_at=now,
            retention_until=retention_until,
            envelope=envelope,
        )
        record = EvidenceVaultRecord(**record.core(), record_digest=record.digest())
        initial = _new_event(
            record,
            (),
            action=VaultCustodyAction.INGESTED,
            actor_id=actor_id,
            purpose=purpose,
            now=now,
            details={"record_digest": record.digest(), "envelope_digest": envelope.digest()},
        )
        self.backend.create(record, initial)
        return record

    def verify(self, evidence_id: str) -> EvidenceVaultState:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        return verify_vault_history(record, self.backend.load_events(evidence_id))

    def access(self, evidence_id: str, *, actor_id: str, purpose: str, now: datetime) -> bytes:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        events = self.backend.load_events(evidence_id)
        verify_vault_history(record, events)
        plaintext = decrypt_bytes(
            record.envelope,
            institution_context=self.institution_context,
            provider=self.provider,
        )
        if len(plaintext) != record.size_bytes:
            raise EvidenceVaultError("Decrypted evidence size does not match immutable metadata.")
        event = _new_event(
            record,
            events,
            action=VaultCustodyAction.ACCESSED,
            actor_id=actor_id,
            purpose=purpose,
            now=now,
        )
        self.backend.append_event(event)
        return plaintext

    def apply_legal_hold(
        self,
        evidence_id: str,
        *,
        hold_id: str,
        reason: str,
        actor_id: str,
        now: datetime,
    ) -> EvidenceVaultState:
        return self._append_lifecycle_event(
            evidence_id,
            action=VaultCustodyAction.LEGAL_HOLD_APPLIED,
            actor_id=actor_id,
            purpose="Apply legal hold.",
            now=now,
            details={"hold_id": _identifier(hold_id, "hold_id"), "reason": _bounded(reason, "reason", maximum=1000)},
        )

    def release_legal_hold(
        self,
        evidence_id: str,
        *,
        hold_id: str,
        reason: str,
        actor_id: str,
        now: datetime,
    ) -> EvidenceVaultState:
        return self._append_lifecycle_event(
            evidence_id,
            action=VaultCustodyAction.LEGAL_HOLD_RELEASED,
            actor_id=actor_id,
            purpose="Release legal hold.",
            now=now,
            details={"hold_id": _identifier(hold_id, "hold_id"), "reason": _bounded(reason, "reason", maximum=1000)},
        )

    def extend_retention(
        self,
        evidence_id: str,
        *,
        retention_until: date,
        actor_id: str,
        reason: str,
        now: datetime,
    ) -> EvidenceVaultState:
        return self._append_lifecycle_event(
            evidence_id,
            action=VaultCustodyAction.RETENTION_EXTENDED,
            actor_id=actor_id,
            purpose=_bounded(reason, "reason", maximum=1000),
            now=now,
            details={"retention_until": _date(retention_until, "retention_until").isoformat()},
        )

    def deletion_eligibility(self, evidence_id: str, *, now: datetime) -> DeletionEligibility:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        state = verify_vault_history(record, self.backend.load_events(evidence_id))
        return evaluate_deletion_eligibility(record, state, now=now)

    def approve_deletion(
        self,
        evidence_id: str,
        *,
        actor_id: str,
        rationale: str,
        now: datetime,
    ) -> DeletionEligibility:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        events = self.backend.load_events(evidence_id)
        state = verify_vault_history(record, events)
        eligibility = evaluate_deletion_eligibility(record, state, now=now)
        if not eligibility.eligible:
            raise EvidenceVaultError(
                "Evidence is not eligible for deletion approval: " + ", ".join(eligibility.reasons)
            )
        event = _new_event(
            record,
            events,
            action=VaultCustodyAction.DELETION_APPROVED,
            actor_id=actor_id,
            purpose=_bounded(rationale, "rationale", maximum=1000),
            now=now,
            details={
                "eligibility": eligibility.as_dict(),
                "destructive_delete_executed": False,
            },
        )
        self.backend.append_event(event)
        return eligibility

    def export_recovery_bundle(
        self,
        evidence_id: str,
        *,
        actor_id: str,
        recipient: str,
        purpose: str,
        now: datetime,
    ) -> EvidenceVaultRecoveryBundle:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        events = self.backend.load_events(evidence_id)
        verify_vault_history(record, events)
        event = _new_event(
            record,
            events,
            action=VaultCustodyAction.EXPORTED,
            actor_id=actor_id,
            purpose=purpose,
            now=now,
            details={"recipient": _bounded(recipient, "recipient", maximum=512)},
        )
        self.backend.append_event(event)
        complete = (*events, event)
        bundle = EvidenceVaultRecoveryBundle(
            record=record,
            custody_events=complete,
            exported_at=now,
            exported_by=actor_id,
            purpose=purpose,
        )
        return EvidenceVaultRecoveryBundle(**bundle.core(), bundle_digest=bundle.digest())

    def restore_recovery_bundle(
        self,
        bundle: EvidenceVaultRecoveryBundle,
        *,
        actor_id: str,
        purpose: str,
        now: datetime,
    ) -> EvidenceVaultState:
        record = bundle.record
        self._assert_record(record)
        verify_vault_history(record, bundle.custody_events)
        plaintext = decrypt_bytes(
            record.envelope,
            institution_context=self.institution_context,
            provider=self.provider,
        )
        if len(plaintext) != record.size_bytes:
            raise EvidenceVaultError("Recovery bundle evidence size is invalid.")
        del plaintext
        restore_event = _new_event(
            record,
            bundle.custody_events,
            action=VaultCustodyAction.RESTORED,
            actor_id=actor_id,
            purpose=purpose,
            now=now,
            details={"recovery_bundle_digest": bundle.digest()},
        )
        self.backend.restore(record, (*bundle.custody_events, restore_event))
        return verify_vault_history(record, (*bundle.custody_events, restore_event))

    def _append_lifecycle_event(
        self,
        evidence_id: str,
        *,
        action: VaultCustodyAction,
        actor_id: str,
        purpose: str,
        now: datetime,
        details: Mapping[str, Any],
    ) -> EvidenceVaultState:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        events = self.backend.load_events(evidence_id)
        verify_vault_history(record, events)
        event = _new_event(
            record,
            events,
            action=action,
            actor_id=actor_id,
            purpose=purpose,
            now=now,
            details=details,
        )
        prospective = (*events, event)
        state = verify_vault_history(record, prospective)
        self.backend.append_event(event)
        return state

    def _assert_record(self, record: EvidenceVaultRecord) -> None:
        if record.institution_id != self.institution_id:
            raise EvidenceVaultError("Vault backend returned evidence for another institution.")


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
            retention_until=_date(document["retention_until"], "retention_until"),
            envelope=envelope_from_document(document["envelope"]),
            record_digest=document["record_digest"],
            schema_version=document["schema_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceVaultError):
            raise
        raise EvidenceVaultError(f"Invalid vault record: {exc}") from exc


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
        retention_until=_date(document["retention_until"], "retention_until"),
        active_hold_ids=tuple(document["active_hold_ids"]),
        record_digest=document["record_digest"],
        custody_head_hash=document["custody_head_hash"],
        state_digest=document["state_digest"],
        eligible=document["eligible"],
        reasons=tuple(document["reasons"]),
        eligibility_digest=document["eligibility_digest"],
        schema_version=document["schema_version"],
    )


def recovery_bundle_from_document(document: Any) -> EvidenceVaultRecoveryBundle:
    fields = {
        "schema_version", "record", "custody_events", "exported_at", "exported_by",
        "purpose", "bundle_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EvidenceVaultError("Recovery bundle does not match the strict v1 contract.")
    if not isinstance(document["custody_events"], list):
        raise EvidenceVaultError("Recovery custody_events must be an array.")
    return EvidenceVaultRecoveryBundle(
        record=vault_record_from_document(document["record"]),
        custody_events=tuple(custody_event_from_document(item) for item in document["custody_events"]),
        exported_at=parse_datetime(document["exported_at"]),
        exported_by=document["exported_by"],
        purpose=document["purpose"],
        bundle_digest=document["bundle_digest"],
        schema_version=document["schema_version"],
    )
