"""KMS/HSM-backed signatures for audit chains and execution receipts."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .audit import AuditChain
from .crypto_provider import CryptoProviderError, KmsHsmProvider, ProviderSignature
from .institution import InstitutionSecurityContext
from .models import ExecutionReceipt, canonical_json, ensure_aware, parse_datetime, sha256_digest, to_primitive

_SCHEMA = "finredops.key-backed-signature.v1"
_PURPOSES = frozenset({"audit_chain", "execution_receipt"})
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")


class KeyBackedSignatureError(ValueError):
    """Raised when a signature artifact is malformed or cannot be verified."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise KeyBackedSignatureError("Signature must be bounded base64url text.")
    try:
        data = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception as exc:
        raise KeyBackedSignatureError("Signature is not valid base64url data.") from exc
    if not data or len(data) > 8_192 or _b64url(data) != value:
        raise KeyBackedSignatureError("Signature is not canonical bounded base64url data.")
    return data


def _key_ref_digest(key_ref: str) -> str:
    return hashlib.sha256(key_ref.encode("utf-8")).hexdigest()


def _digest_bytes(document: Mapping[str, Any]) -> tuple[str, bytes]:
    encoded = canonical_json(document).encode("utf-8")
    digest = hashlib.sha256(encoded).digest()
    return digest.hex(), digest


@dataclass(frozen=True, slots=True)
class KeyBackedSignatureArtifact:
    institution_id: str
    purpose: str
    object_id: str
    object_digest: str
    key_id: str
    provider: str
    key_ref_digest: str
    signing_algorithm: str
    signature: str
    signed_at: datetime
    signing_document_digest: str
    artifact_digest: str = ""
    schema_version: str = _SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA:
            raise KeyBackedSignatureError("Unsupported key-backed signature schema.")
        if self.purpose not in _PURPOSES:
            raise KeyBackedSignatureError("Unsupported key-backed signature purpose.")
        for value, name in (
            (self.institution_id, "institution_id"),
            (self.object_id, "object_id"),
            (self.key_id, "key_id"),
            (self.provider, "provider"),
            (self.signing_algorithm, "signing_algorithm"),
        ):
            if not isinstance(value, str) or not _TEXT.fullmatch(value):
                raise KeyBackedSignatureError(f"{name} must be bounded printable text.")
        for value, name in (
            (self.object_digest, "object_digest"),
            (self.key_ref_digest, "key_ref_digest"),
            (self.signing_document_digest, "signing_document_digest"),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise KeyBackedSignatureError(f"{name} must be a lowercase SHA-256 digest.")
        _decode_b64url(self.signature)
        object.__setattr__(self, "signed_at", ensure_aware(self.signed_at))
        if self.artifact_digest:
            if not _DIGEST.fullmatch(self.artifact_digest):
                raise KeyBackedSignatureError("artifact_digest must be a lowercase SHA-256 digest.")
            if self.artifact_digest != self.digest():
                raise KeyBackedSignatureError("Signature artifact digest is invalid.")

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.key-backed-signing-document.v1",
            "institution_id": self.institution_id,
            "purpose": self.purpose,
            "object_id": self.object_id,
            "object_digest": self.object_digest,
            "key_id": self.key_id,
            "provider": self.provider,
            "key_ref_digest": self.key_ref_digest,
            "signed_at": self.signed_at,
        }

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "purpose": self.purpose,
            "object_id": self.object_id,
            "object_digest": self.object_digest,
            "key_id": self.key_id,
            "provider": self.provider,
            "key_ref_digest": self.key_ref_digest,
            "signing_algorithm": self.signing_algorithm,
            "signature": self.signature,
            "signed_at": self.signed_at,
            "signing_document_digest": self.signing_document_digest,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "artifact_digest": self.digest()}


def key_backed_signature_from_document(document: Any) -> KeyBackedSignatureArtifact:
    fields = {
        "schema_version",
        "institution_id",
        "purpose",
        "object_id",
        "object_digest",
        "key_id",
        "provider",
        "key_ref_digest",
        "signing_algorithm",
        "signature",
        "signed_at",
        "signing_document_digest",
        "artifact_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise KeyBackedSignatureError("Signature artifact does not match the strict v1 contract.")
    try:
        return KeyBackedSignatureArtifact(
            institution_id=document["institution_id"],
            purpose=document["purpose"],
            object_id=document["object_id"],
            object_digest=document["object_digest"],
            key_id=document["key_id"],
            provider=document["provider"],
            key_ref_digest=document["key_ref_digest"],
            signing_algorithm=document["signing_algorithm"],
            signature=document["signature"],
            signed_at=parse_datetime(document["signed_at"]),
            signing_document_digest=document["signing_document_digest"],
            artifact_digest=document["artifact_digest"],
            schema_version=document["schema_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, KeyBackedSignatureError):
            raise
        raise KeyBackedSignatureError(f"Invalid key-backed signature artifact: {exc}") from exc


def _sign(
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    purpose: str,
    object_id: str,
    object_digest: str,
    signed_at: datetime,
) -> KeyBackedSignatureArtifact:
    signed_at = ensure_aware(signed_at)
    key = institution_context.active_key("audit_signing")
    if provider.provider_name != key.provider:
        raise KeyBackedSignatureError("Crypto provider does not match the active audit-signing key.")
    key_digest = _key_ref_digest(key.key_ref)
    signing_document = {
        "schema_version": "finredops.key-backed-signing-document.v1",
        "institution_id": institution_context.institution_id,
        "purpose": purpose,
        "object_id": object_id,
        "object_digest": object_digest,
        "key_id": key.key_id,
        "provider": key.provider,
        "key_ref_digest": key_digest,
        "signed_at": signed_at,
    }
    signing_document_digest, digest = _digest_bytes(signing_document)
    try:
        produced = provider.sign_digest(key.key_ref, digest)
    except CryptoProviderError as exc:
        raise KeyBackedSignatureError("Institution KMS/HSM failed to sign the artifact digest.") from exc
    artifact = KeyBackedSignatureArtifact(
        institution_id=institution_context.institution_id,
        purpose=purpose,
        object_id=object_id,
        object_digest=object_digest,
        key_id=key.key_id,
        provider=key.provider,
        key_ref_digest=key_digest,
        signing_algorithm=produced.algorithm,
        signature=_b64url(produced.signature),
        signed_at=signed_at,
        signing_document_digest=signing_document_digest,
    )
    return KeyBackedSignatureArtifact(**artifact.core(), artifact_digest=artifact.digest())


def _verify(
    artifact: KeyBackedSignatureArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    expected_purpose: str,
    expected_object_id: str,
    expected_object_digest: str,
) -> bool:
    if (
        artifact.purpose != expected_purpose
        or artifact.object_id != expected_object_id
        or artifact.object_digest != expected_object_digest
        or artifact.institution_id != institution_context.institution_id
    ):
        return False
    try:
        key = institution_context.key_by_id(artifact.key_id)
    except Exception:
        return False
    if key.status == "disabled":
        return False
    if key.provider != artifact.provider or provider.provider_name != artifact.provider:
        return False
    if _key_ref_digest(key.key_ref) != artifact.key_ref_digest:
        return False
    signing_document_digest, digest = _digest_bytes(artifact.signing_document())
    if signing_document_digest != artifact.signing_document_digest:
        return False
    try:
        return provider.verify_digest(
            key.key_ref,
            digest,
            ProviderSignature(_decode_b64url(artifact.signature), artifact.signing_algorithm),
        )
    except CryptoProviderError:
        return False


def audit_chain_target(engagement_id: str, chain: AuditChain) -> dict[str, Any]:
    valid, errors = chain.verify()
    if not valid:
        raise KeyBackedSignatureError("Cannot sign an invalid audit chain: " + " ".join(errors))
    if any(event.engagement_id != engagement_id for event in chain.events):
        raise KeyBackedSignatureError("Audit chain contains an event for another engagement.")
    return {
        "schema_version": "finredops.audit-signature-target.v1",
        "engagement_id": engagement_id,
        "event_count": len(chain.events),
        "head_event_hash": chain.events[-1].event_hash if chain.events else "0" * 64,
        "audit_document_digest": sha256_digest(chain.as_list()),
    }


def sign_audit_chain(
    engagement_id: str,
    chain: AuditChain,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    signed_at: datetime,
) -> KeyBackedSignatureArtifact:
    target = audit_chain_target(engagement_id, chain)
    return _sign(
        institution_context=institution_context,
        provider=provider,
        purpose="audit_chain",
        object_id=engagement_id,
        object_digest=sha256_digest(target),
        signed_at=signed_at,
    )


def verify_audit_chain_signature(
    engagement_id: str,
    chain: AuditChain,
    artifact: KeyBackedSignatureArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
) -> bool:
    target = audit_chain_target(engagement_id, chain)
    return _verify(
        artifact,
        institution_context=institution_context,
        provider=provider,
        expected_purpose="audit_chain",
        expected_object_id=engagement_id,
        expected_object_digest=sha256_digest(target),
    )


def receipt_target(receipt: ExecutionReceipt) -> dict[str, Any]:
    return {
        "schema_version": "finredops.receipt-signature-target.v1",
        "execution_id": receipt.execution_id,
        "proposal_id": receipt.proposal_id,
        "proposal_digest": receipt.proposal_digest,
        "status": receipt.status,
        "runner": receipt.runner,
        "started_at": receipt.started_at,
        "finished_at": receipt.finished_at,
        "evidence_digest": receipt.evidence_digest,
        "receipt_digest": sha256_digest(to_primitive(receipt)),
    }


def sign_execution_receipt(
    receipt: ExecutionReceipt,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    signed_at: datetime,
) -> KeyBackedSignatureArtifact:
    target = receipt_target(receipt)
    return _sign(
        institution_context=institution_context,
        provider=provider,
        purpose="execution_receipt",
        object_id=receipt.execution_id,
        object_digest=sha256_digest(target),
        signed_at=signed_at,
    )


def verify_execution_receipt_signature(
    receipt: ExecutionReceipt,
    artifact: KeyBackedSignatureArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
) -> bool:
    target = receipt_target(receipt)
    return _verify(
        artifact,
        institution_context=institution_context,
        provider=provider,
        expected_purpose="execution_receipt",
        expected_object_id=receipt.execution_id,
        expected_object_digest=sha256_digest(target),
    )
