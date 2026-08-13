"""Offline verification for independent audit-anchor receipts."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor_models import AuditAnchorCommitment, AuditAnchorError, AuditAnchorReceipt, AuditAnchorTrustBundle, decode_b64url
from .models import canonical_json

GENESIS_RECEIPT_DIGEST = "0" * 64


def _digest_bytes(document: dict[str, object]) -> tuple[str, bytes]:
    value = hashlib.sha256(canonical_json(document).encode("utf-8")).digest()
    return value.hex(), value


def _signature_valid(receipt: AuditAnchorReceipt, trust_bundle: AuditAnchorTrustBundle) -> bool:
    try:
        key = trust_bundle.key_by_id(receipt.key_id)
        if key.status == "disabled" or not (key.not_before <= receipt.anchored_at <= key.not_after):
            return False
        digest_hex, digest = _digest_bytes(receipt.signing_document())
        if digest_hex != receipt.signing_document_digest:
            return False
        Ed25519PublicKey.from_public_bytes(decode_b64url(key.public_key, max_bytes=64)).verify(
            decode_b64url(receipt.signature), digest
        )
    except (AuditAnchorError, InvalidSignature, ValueError):
        return False
    return receipt.receipt_digest == receipt.digest()


def verify_audit_anchor_receipt(
    commitment: AuditAnchorCommitment,
    receipt: AuditAnchorReceipt,
    *,
    trust_bundle: AuditAnchorTrustBundle,
    expected_previous_receipt_digest: str | None = None,
    expected_sequence: int | None = None,
) -> bool:
    if receipt.anchor_id != trust_bundle.anchor_id:
        return False
    if receipt.institution_id != commitment.institution_id or receipt.engagement_id != commitment.engagement_id:
        return False
    if receipt.commitment_digest != commitment.digest():
        return False
    if expected_sequence is not None and receipt.sequence != expected_sequence:
        return False
    if expected_previous_receipt_digest is not None and receipt.previous_receipt_digest != expected_previous_receipt_digest:
        return False
    return _signature_valid(receipt, trust_bundle)


def verify_audit_anchor_chain(
    receipts: Iterable[AuditAnchorReceipt],
    *,
    trust_bundle: AuditAnchorTrustBundle,
) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    previous = GENESIS_RECEIPT_DIGEST
    previous_time: datetime | None = None
    seen: set[str] = set()
    for expected_sequence, receipt in enumerate(receipts, start=1):
        if receipt.anchor_id != trust_bundle.anchor_id:
            errors.append(f"Receipt {expected_sequence}: anchor id mismatch.")
        if receipt.sequence != expected_sequence:
            errors.append(f"Receipt {expected_sequence}: invalid sequence {receipt.sequence}.")
        if receipt.previous_receipt_digest != previous:
            errors.append(f"Receipt {expected_sequence}: previous receipt digest mismatch.")
        if receipt.commitment_digest in seen:
            errors.append(f"Receipt {expected_sequence}: duplicate commitment digest.")
        if previous_time is not None and receipt.anchored_at < previous_time:
            errors.append(f"Receipt {expected_sequence}: anchor timestamp moves backwards.")
        if not _signature_valid(receipt, trust_bundle):
            errors.append(f"Receipt {expected_sequence}: signature/trust verification failed.")
        previous = receipt.digest()
        previous_time = receipt.anchored_at
        seen.add(receipt.commitment_digest)
    return not errors, tuple(errors)
