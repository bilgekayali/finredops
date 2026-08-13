"""Deterministic verification of evidence-vault custody history."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .vault_common import (
    EvidenceVaultError,
    EvidenceVaultRecord,
    VaultCustodyAction,
    bounded_text,
    digest_text,
    identifier,
    retention_date,
)
from .vault_custody import (
    EvidenceVaultState,
    VaultCustodyEvent,
    deletion_eligibility_from_document,
    evaluate_deletion_eligibility,
)


def _exact(details: Mapping[str, Any], fields: set[str], action: str) -> dict[str, Any]:
    normalized = dict(details)
    if set(normalized) != fields:
        raise EvidenceVaultError(f"{action} custody details do not match the strict contract.")
    return normalized


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
    last_timestamp = record.collected_at

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
        if not event.event_hash or event.event_hash != event.digest():
            raise EvidenceVaultError("Custody event hash is invalid.")
        if event.timestamp < record.collected_at or event.timestamp < last_timestamp:
            raise EvidenceVaultError("Custody timestamps must be monotonic after collection.")

        details = dict(event.details)
        if index == 1:
            if event.action != VaultCustodyAction.INGESTED:
                raise EvidenceVaultError("Evidence custody must begin with ingest.")
            details = _exact(details, {"record_digest", "envelope_digest"}, "ingest")
            if details != {
                "record_digest": record.digest(),
                "envelope_digest": record.envelope.digest(),
            }:
                raise EvidenceVaultError("Ingest event is not bound to the vault record and envelope.")
        elif event.action == VaultCustodyAction.INGESTED:
            raise EvidenceVaultError("Evidence can have only one ingest event.")
        elif event.action == VaultCustodyAction.ACCESSED:
            if details:
                raise EvidenceVaultError("Access custody event must not embed evidence data.")
        elif event.action == VaultCustodyAction.EXPORTED:
            details = _exact(details, {"recipient"}, "export")
            bounded_text(details["recipient"], "export recipient", maximum=512)
        elif event.action == VaultCustodyAction.LEGAL_HOLD_APPLIED:
            details = _exact(details, {"hold_id", "reason"}, "legal hold")
            hold_id = identifier(details["hold_id"], "hold_id")
            bounded_text(details["reason"], "hold reason", maximum=1000)
            if hold_id in seen_holds:
                raise EvidenceVaultError("Legal-hold identifier cannot be reused.")
            seen_holds.add(hold_id)
            active_holds.add(hold_id)
        elif event.action == VaultCustodyAction.LEGAL_HOLD_RELEASED:
            details = _exact(details, {"hold_id", "reason"}, "legal hold release")
            hold_id = identifier(details["hold_id"], "hold_id")
            bounded_text(details["reason"], "hold release reason", maximum=1000)
            if hold_id not in active_holds:
                raise EvidenceVaultError("Only an active legal hold can be released.")
            active_holds.remove(hold_id)
        elif event.action == VaultCustodyAction.RETENTION_EXTENDED:
            details = _exact(details, {"retention_until"}, "retention extension")
            new_until = retention_date(details["retention_until"])
            if new_until <= retention_until:
                raise EvidenceVaultError("Retention may only be extended, never shortened.")
            retention_until = new_until
        elif event.action == VaultCustodyAction.DELETION_APPROVED:
            details = _exact(
                details,
                {"eligibility", "destructive_delete_executed"},
                "deletion approval",
            )
            if details["destructive_delete_executed"] is not False:
                raise EvidenceVaultError("Deletion approval must not claim destructive execution.")
            eligibility = deletion_eligibility_from_document(details["eligibility"])
            before = EvidenceVaultState(
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
            expected = evaluate_deletion_eligibility(record, before, now=event.timestamp)
            if eligibility.as_dict() != expected.as_dict() or not eligibility.eligible:
                raise EvidenceVaultError("Deletion approval is not bound to current eligible state.")
            latest_deletion = eligibility.digest()
        elif event.action == VaultCustodyAction.RESTORED:
            details = _exact(details, {"recovery_bundle_digest"}, "restore")
            digest_text(details["recovery_bundle_digest"], "recovery_bundle_digest")
        else:
            raise EvidenceVaultError("Unknown custody action.")

        previous = event.digest()
        last_timestamp = event.timestamp

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
