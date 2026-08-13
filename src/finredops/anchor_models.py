"""Strict data contracts for independent audit-anchor commitments and receipts."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive

COMMITMENT_SCHEMA = "finredops.audit-anchor-commitment.v1"
RECEIPT_SCHEMA = "finredops.audit-anchor-receipt.v1"
TRUST_SCHEMA = "finredops.audit-anchor-trust-bundle.v1"
SIGNING_DOCUMENT_SCHEMA = "finredops.audit-anchor-receipt-signing-document.v1"
DIGEST = re.compile(r"^[a-f0-9]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$")


class AuditAnchorError(ValueError):
    pass


def require_digest(value: str, name: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise AuditAnchorError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def require_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise AuditAnchorError(f"{name} must be a bounded identifier.")
    return value


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_b64url(value: str, *, max_bytes: int = 8192) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_bytes * 2:
        raise AuditAnchorError("Encoded key/signature value is not bounded base64url text.")
    try:
        decoded = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception as exc:
        raise AuditAnchorError("Encoded key/signature value is not valid base64url.") from exc
    if not decoded or len(decoded) > max_bytes or b64url(decoded) != value:
        raise AuditAnchorError("Encoded key/signature value is not canonical base64url.")
    return decoded


@dataclass(frozen=True, slots=True)
class AuditAnchorCommitment:
    institution_id: str
    engagement_id: str
    event_count: int
    head_event_hash: str
    audit_document_digest: str
    audit_target_digest: str
    audit_signature_artifact_digest: str
    source_artifact_digest: str
    commitment_digest: str = ""
    schema_version: str = COMMITMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMMITMENT_SCHEMA:
            raise AuditAnchorError("Unsupported audit-anchor commitment schema.")
        require_identifier(self.institution_id, "institution_id")
        require_identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.event_count, int) or isinstance(self.event_count, bool) or not 0 <= self.event_count <= 10_000_000:
            raise AuditAnchorError("event_count must be a bounded non-negative integer.")
        for value, name in ((self.head_event_hash, "head_event_hash"), (self.audit_document_digest, "audit_document_digest"), (self.audit_target_digest, "audit_target_digest"), (self.audit_signature_artifact_digest, "audit_signature_artifact_digest"), (self.source_artifact_digest, "source_artifact_digest")):
            require_digest(value, name)
        if self.commitment_digest:
            require_digest(self.commitment_digest, "commitment_digest")
            if self.commitment_digest != self.digest():
                raise AuditAnchorError("Audit-anchor commitment digest is invalid.")

    def core(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "institution_id": self.institution_id, "engagement_id": self.engagement_id, "event_count": self.event_count, "head_event_hash": self.head_event_hash, "audit_document_digest": self.audit_document_digest, "audit_target_digest": self.audit_target_digest, "audit_signature_artifact_digest": self.audit_signature_artifact_digest, "source_artifact_digest": self.source_artifact_digest}

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "commitment_digest": self.digest()}


def commitment_from_document(document: Any) -> AuditAnchorCommitment:
    fields = {"schema_version", "institution_id", "engagement_id", "event_count", "head_event_hash", "audit_document_digest", "audit_target_digest", "audit_signature_artifact_digest", "source_artifact_digest", "commitment_digest"}
    if not isinstance(document, Mapping) or set(document) != fields:
        raise AuditAnchorError("Audit-anchor commitment does not match the strict v1 contract.")
    return AuditAnchorCommitment(**document)


@dataclass(frozen=True, slots=True)
class AuditAnchorTrustKey:
    key_id: str
    public_key: str
    not_before: datetime
    not_after: datetime
    status: str = "active"

    def __post_init__(self) -> None:
        require_identifier(self.key_id, "key_id")
        if len(decode_b64url(self.public_key, max_bytes=64)) != 32:
            raise AuditAnchorError("Anchor Ed25519 public key must be exactly 32 bytes.")
        object.__setattr__(self, "not_before", ensure_aware(self.not_before))
        object.__setattr__(self, "not_after", ensure_aware(self.not_after))
        if self.not_after <= self.not_before or self.status not in {"active", "retiring", "disabled"}:
            raise AuditAnchorError("Anchor trust-key state/window is invalid.")


@dataclass(frozen=True, slots=True)
class AuditAnchorTrustBundle:
    anchor_id: str
    keys: tuple[AuditAnchorTrustKey, ...]
    bundle_digest: str = ""
    schema_version: str = TRUST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != TRUST_SCHEMA:
            raise AuditAnchorError("Unsupported audit-anchor trust-bundle schema.")
        require_identifier(self.anchor_id, "anchor_id")
        if not self.keys or len(self.keys) > 128:
            raise AuditAnchorError("Anchor trust bundle must contain a bounded key set.")
        if len({key.key_id for key in self.keys}) != len(self.keys) or len({key.public_key for key in self.keys}) != len(self.keys):
            raise AuditAnchorError("Anchor trust keys and public keys must be unique.")
        if self.bundle_digest and self.bundle_digest != self.digest():
            raise AuditAnchorError("Anchor trust-bundle digest is invalid.")

    def core(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "anchor_id": self.anchor_id, "keys": [to_primitive(key) for key in self.keys]}

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**self.core(), "bundle_digest": self.digest()}

    def key_by_id(self, key_id: str) -> AuditAnchorTrustKey:
        matches = [key for key in self.keys if key.key_id == key_id]
        if len(matches) != 1:
            raise AuditAnchorError("Anchor receipt key is not uniquely trusted.")
        return matches[0]


def trust_bundle_from_document(document: Any) -> AuditAnchorTrustBundle:
    if not isinstance(document, Mapping) or set(document) != {"schema_version", "anchor_id", "keys", "bundle_digest"}:
        raise AuditAnchorError("Anchor trust bundle does not match the strict v1 contract.")
    raw_keys = document["keys"]
    if not isinstance(raw_keys, list):
        raise AuditAnchorError("Anchor trust keys must be a list.")
    keys = []
    for raw in raw_keys:
        if not isinstance(raw, Mapping) or set(raw) != {"key_id", "public_key", "not_before", "not_after", "status"}:
            raise AuditAnchorError("Anchor trust key does not match the strict v1 contract.")
        keys.append(AuditAnchorTrustKey(raw["key_id"], raw["public_key"], parse_datetime(raw["not_before"]), parse_datetime(raw["not_after"]), raw["status"]))
    return AuditAnchorTrustBundle(document["anchor_id"], tuple(keys), document["bundle_digest"], document["schema_version"])


@dataclass(frozen=True, slots=True)
class AuditAnchorReceipt:
    anchor_id: str
    sequence: int
    institution_id: str
    engagement_id: str
    commitment_digest: str
    previous_receipt_digest: str
    anchored_at: datetime
    key_id: str
    signature_algorithm: str
    signature: str
    signing_document_digest: str
    receipt_digest: str = ""
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise AuditAnchorError("Unsupported audit-anchor receipt schema.")
        for value, name in ((self.anchor_id, "anchor_id"), (self.institution_id, "institution_id"), (self.engagement_id, "engagement_id"), (self.key_id, "key_id")):
            require_identifier(value, name)
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise AuditAnchorError("Anchor receipt sequence must be positive.")
        for value, name in ((self.commitment_digest, "commitment_digest"), (self.previous_receipt_digest, "previous_receipt_digest"), (self.signing_document_digest, "signing_document_digest")):
            require_digest(value, name)
        if self.signature_algorithm != "Ed25519-SHA256-DIGEST":
            raise AuditAnchorError("Unsupported anchor receipt signature algorithm.")
        decode_b64url(self.signature)
        object.__setattr__(self, "anchored_at", ensure_aware(self.anchored_at))
        if self.receipt_digest and self.receipt_digest != self.digest():
            raise AuditAnchorError("Audit-anchor receipt digest is invalid.")

    def signing_document(self) -> dict[str, Any]:
        return {"schema_version": SIGNING_DOCUMENT_SCHEMA, "anchor_id": self.anchor_id, "sequence": self.sequence, "institution_id": self.institution_id, "engagement_id": self.engagement_id, "commitment_digest": self.commitment_digest, "previous_receipt_digest": self.previous_receipt_digest, "anchored_at": self.anchored_at, "key_id": self.key_id}

    def core(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "anchor_id": self.anchor_id, "sequence": self.sequence, "institution_id": self.institution_id, "engagement_id": self.engagement_id, "commitment_digest": self.commitment_digest, "previous_receipt_digest": self.previous_receipt_digest, "anchored_at": self.anchored_at, "key_id": self.key_id, "signature_algorithm": self.signature_algorithm, "signature": self.signature, "signing_document_digest": self.signing_document_digest}

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "receipt_digest": self.digest()}


def receipt_from_document(document: Any) -> AuditAnchorReceipt:
    fields = {"schema_version", "anchor_id", "sequence", "institution_id", "engagement_id", "commitment_digest", "previous_receipt_digest", "anchored_at", "key_id", "signature_algorithm", "signature", "signing_document_digest", "receipt_digest"}
    if not isinstance(document, Mapping) or set(document) != fields:
        raise AuditAnchorError("Audit-anchor receipt does not match the strict v1 contract.")
    return AuditAnchorReceipt(document["anchor_id"], document["sequence"], document["institution_id"], document["engagement_id"], document["commitment_digest"], document["previous_receipt_digest"], parse_datetime(document["anchored_at"]), document["key_id"], document["signature_algorithm"], document["signature"], document["signing_document_digest"], document["receipt_digest"], document["schema_version"])
