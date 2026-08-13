"""Institution-bound encrypted evidence-vault service."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .crypto_provider import KmsHsmProvider
from .envelope import decrypt_bytes, encrypt_bytes
from .institution import InstitutionSecurityContext
from .models import DataClassification, ensure_aware
from .vault_bundle import EvidenceVaultRecoveryBundle
from .vault_common import (
    EvidenceVaultError,
    EvidenceVaultRecord,
    VaultCustodyAction,
    bounded_text,
    identifier,
    retention_date,
)
from .vault_custody import (
    DeletionEligibility,
    EvidenceVaultState,
    VaultCustodyEvent,
    evaluate_deletion_eligibility,
    new_custody_event,
)
from .vault_history import verify_vault_history


@runtime_checkable
class EvidenceVaultBackend(Protocol):
    """Persistence boundary for encrypted records and append-only custody."""

    institution_id: str

    def create(self, record: EvidenceVaultRecord, initial_event: VaultCustodyEvent) -> None: ...
    def load_record(self, evidence_id: str) -> EvidenceVaultRecord: ...
    def load_events(self, evidence_id: str) -> tuple[VaultCustodyEvent, ...]: ...
    def append_event(self, event: VaultCustodyEvent) -> None: ...
    def restore(self, record: EvidenceVaultRecord, events: Sequence[VaultCustodyEvent]) -> None: ...
    def metadata(self) -> Mapping[str, Any]: ...


class EvidenceVault:
    """Lifecycle service that never exposes a destructive delete operation."""

    def __init__(
        self,
        *,
        institution_context: InstitutionSecurityContext,
        provider: KmsHsmProvider,
        backend: EvidenceVaultBackend,
    ) -> None:
        if backend.institution_id != institution_context.institution_id:
            raise EvidenceVaultError("Vault backend and institution context do not match.")
        active_key = institution_context.active_key("data_encryption")
        if provider.provider_name != active_key.provider:
            raise EvidenceVaultError("Vault crypto provider does not match the active institution key.")
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
    ) -> EvidenceVaultRecord:
        if not isinstance(content, bytes):
            raise EvidenceVaultError("Evidence content must be bytes.")
        engagement_id = identifier(engagement_id, "engagement_id")
        evidence_id = identifier(evidence_id, "evidence_id")
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
        ).sealed()
        initial = new_custody_event(
            record,
            (),
            action=VaultCustodyAction.INGESTED,
            actor_id=actor_id,
            purpose="Ingest encrypted evidence into the institution vault.",
            now=now,
            details={
                "record_digest": record.digest(),
                "envelope_digest": envelope.digest(),
            },
        )
        self.backend.create(record, initial)
        return record

    def verify(self, evidence_id: str) -> EvidenceVaultState:
        record, events = self._load(evidence_id)
        return verify_vault_history(record, events)

    def access(
        self,
        evidence_id: str,
        *,
        actor_id: str,
        purpose: str,
        now: datetime,
    ) -> bytes:
        record, events = self._load(evidence_id)
        verify_vault_history(record, events)
        plaintext = decrypt_bytes(
            record.envelope,
            institution_context=self.institution_context,
            provider=self.provider,
        )
        if len(plaintext) != record.size_bytes:
            raise EvidenceVaultError("Decrypted evidence size does not match immutable metadata.")
        event = new_custody_event(
            record,
            events,
            action=VaultCustodyAction.ACCESSED,
            actor_id=actor_id,
            purpose=bounded_text(purpose, "purpose", maximum=1000),
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
        return self._append(
            evidence_id,
            action=VaultCustodyAction.LEGAL_HOLD_APPLIED,
            actor_id=actor_id,
            purpose="Apply legal hold.",
            now=now,
            details={
                "hold_id": identifier(hold_id, "hold_id"),
                "reason": bounded_text(reason, "reason", maximum=1000),
            },
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
        return self._append(
            evidence_id,
            action=VaultCustodyAction.LEGAL_HOLD_RELEASED,
            actor_id=actor_id,
            purpose="Release legal hold.",
            now=now,
            details={
                "hold_id": identifier(hold_id, "hold_id"),
                "reason": bounded_text(reason, "reason", maximum=1000),
            },
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
        return self._append(
            evidence_id,
            action=VaultCustodyAction.RETENTION_EXTENDED,
            actor_id=actor_id,
            purpose=bounded_text(reason, "reason", maximum=1000),
            now=now,
            details={"retention_until": retention_date(retention_until).isoformat()},
        )

    def deletion_eligibility(
        self,
        evidence_id: str,
        *,
        now: datetime,
    ) -> DeletionEligibility:
        record, events = self._load(evidence_id)
        state = verify_vault_history(record, events)
        return evaluate_deletion_eligibility(record, state, now=now)

    def approve_deletion(
        self,
        evidence_id: str,
        *,
        actor_id: str,
        rationale: str,
        now: datetime,
    ) -> DeletionEligibility:
        record, events = self._load(evidence_id)
        state = verify_vault_history(record, events)
        eligibility = evaluate_deletion_eligibility(record, state, now=now)
        if not eligibility.eligible:
            raise EvidenceVaultError(
                "Evidence is not eligible for deletion approval: "
                + ", ".join(eligibility.reasons)
            )
        event = new_custody_event(
            record,
            events,
            action=VaultCustodyAction.DELETION_APPROVED,
            actor_id=actor_id,
            purpose=bounded_text(rationale, "rationale", maximum=1000),
            now=now,
            details={
                "eligibility": eligibility.as_dict(),
                "destructive_delete_executed": False,
            },
        )
        verify_vault_history(record, (*events, event))
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
        record, events = self._load(evidence_id)
        verify_vault_history(record, events)
        event = new_custody_event(
            record,
            events,
            action=VaultCustodyAction.EXPORTED,
            actor_id=actor_id,
            purpose=bounded_text(purpose, "purpose", maximum=1000),
            now=now,
            details={"recipient": bounded_text(recipient, "recipient", maximum=512)},
        )
        self.backend.append_event(event)
        return EvidenceVaultRecoveryBundle(
            record=record,
            custody_events=(*events, event),
            exported_at=ensure_aware(now),
            exported_by=actor_id,
            purpose=purpose,
        ).sealed()

    def restore_recovery_bundle(
        self,
        bundle: EvidenceVaultRecoveryBundle,
        *,
        actor_id: str,
        purpose: str,
        now: datetime,
    ) -> EvidenceVaultState:
        if not isinstance(bundle, EvidenceVaultRecoveryBundle):
            raise EvidenceVaultError("Recovery input must be a verified recovery bundle.")
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
        restore_event = new_custody_event(
            record,
            bundle.custody_events,
            action=VaultCustodyAction.RESTORED,
            actor_id=actor_id,
            purpose=bounded_text(purpose, "purpose", maximum=1000),
            now=now,
            details={"recovery_bundle_digest": bundle.digest()},
        )
        complete = (*bundle.custody_events, restore_event)
        verify_vault_history(record, complete)
        self.backend.restore(record, complete)
        return verify_vault_history(record, complete)

    def _append(
        self,
        evidence_id: str,
        *,
        action: VaultCustodyAction,
        actor_id: str,
        purpose: str,
        now: datetime,
        details: Mapping[str, Any],
    ) -> EvidenceVaultState:
        record, events = self._load(evidence_id)
        verify_vault_history(record, events)
        event = new_custody_event(
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

    def _load(self, evidence_id: str) -> tuple[EvidenceVaultRecord, tuple[VaultCustodyEvent, ...]]:
        record = self.backend.load_record(evidence_id)
        self._assert_record(record)
        return record, self.backend.load_events(evidence_id)

    def _assert_record(self, record: EvidenceVaultRecord) -> None:
        if record.institution_id != self.institution_id:
            raise EvidenceVaultError("Vault backend returned evidence for another institution.")
