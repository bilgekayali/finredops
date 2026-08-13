"""Institution-bound envelope encryption for FinRedOps persistence artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_provider import CryptoProviderError, KmsHsmProvider, WrappedDataKey
from .institution import InstitutionSecurityContext
from .models import canonical_json, ensure_aware, parse_datetime, sha256_digest, to_primitive

_SCHEMA = "finredops.envelope-encrypted-artifact.v1"
_CONTENT_ALGORITHM = "AES-256-GCM"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_BOUNDED_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")


class EnvelopeError(ValueError):
    """Raised when an envelope is invalid or cannot be authenticated/decrypted."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str, *, name: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnvelopeError(f"{name} must be non-empty base64url text.")
    if len(value) > maximum_bytes * 2:
        raise EnvelopeError(f"{name} exceeds the bounded size limit.")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnvelopeError(f"{name} is not valid base64url data.") from exc
    if not decoded or len(decoded) > maximum_bytes:
        raise EnvelopeError(f"{name} exceeds the bounded size limit.")
    if _b64url(decoded) != value:
        raise EnvelopeError(f"{name} is not canonical base64url data.")
    return decoded


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key_ref_digest(key_ref: str) -> str:
    return hashlib.sha256(key_ref.encode("utf-8")).hexdigest()


def _validate_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not _BOUNDED_TEXT.fullmatch(value):
        raise EnvelopeError(f"{name} must be bounded printable text.")
    return value


def _aad_document(
    *,
    institution_id: str,
    object_type: str,
    object_id: str,
    key_id: str,
    provider: str,
    key_ref_digest: str,
) -> dict[str, str]:
    return {
        "schema_version": "finredops.envelope-aad.v1",
        "institution_id": institution_id,
        "object_type": object_type,
        "object_id": object_id,
        "key_id": key_id,
        "provider": provider,
        "key_ref_digest": key_ref_digest,
    }


def _provider_context(aad: Mapping[str, str]) -> dict[str, str]:
    object_binding = sha256_digest(
        {"object_type": aad["object_type"], "object_id": aad["object_id"]}
    )
    return {
        "finredops-envelope": "v1",
        "institution-id": aad["institution_id"],
        "object-binding": object_binding,
        "key-id": aad["key_id"],
    }


@dataclass(frozen=True, slots=True)
class EnvelopeEncryptedArtifact:
    institution_id: str
    object_type: str
    object_id: str
    key_id: str
    provider: str
    key_ref_digest: str
    wrapping_algorithm: str
    nonce: str
    ciphertext: str
    wrapped_dek: str
    plaintext_digest: str
    aad_digest: str
    created_at: datetime
    envelope_digest: str = ""
    content_algorithm: str = _CONTENT_ALGORITHM
    schema_version: str = _SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA:
            raise EnvelopeError("Unsupported envelope schema version.")
        for value, name in (
            (self.institution_id, "institution_id"),
            (self.object_type, "object_type"),
            (self.object_id, "object_id"),
            (self.key_id, "key_id"),
            (self.provider, "provider"),
            (self.wrapping_algorithm, "wrapping_algorithm"),
        ):
            _validate_text(value, name)
        if self.content_algorithm != _CONTENT_ALGORITHM:
            raise EnvelopeError("Unsupported envelope content algorithm.")
        for value, name in (
            (self.key_ref_digest, "key_ref_digest"),
            (self.plaintext_digest, "plaintext_digest"),
            (self.aad_digest, "aad_digest"),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise EnvelopeError(f"{name} must be a lowercase SHA-256 digest.")
        _decode_b64url(self.nonce, name="nonce", maximum_bytes=32)
        if len(_decode_b64url(self.nonce, name="nonce", maximum_bytes=32)) != 12:
            raise EnvelopeError("AES-GCM nonce must be exactly 12 bytes.")
        _decode_b64url(self.ciphertext, name="ciphertext", maximum_bytes=20_000_000)
        _decode_b64url(self.wrapped_dek, name="wrapped_dek", maximum_bytes=16_384)
        object.__setattr__(self, "created_at", ensure_aware(self.created_at))
        if self.envelope_digest:
            if not _DIGEST.fullmatch(self.envelope_digest):
                raise EnvelopeError("envelope_digest must be a lowercase SHA-256 digest.")
            if self.envelope_digest != self.digest():
                raise EnvelopeError("Envelope digest does not match its immutable fields.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "key_id": self.key_id,
            "provider": self.provider,
            "key_ref_digest": self.key_ref_digest,
            "content_algorithm": self.content_algorithm,
            "wrapping_algorithm": self.wrapping_algorithm,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "wrapped_dek": self.wrapped_dek,
            "plaintext_digest": self.plaintext_digest,
            "aad_digest": self.aad_digest,
            "created_at": self.created_at,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "envelope_digest": self.digest()}


def envelope_from_document(document: Any) -> EnvelopeEncryptedArtifact:
    fields = {
        "schema_version",
        "institution_id",
        "object_type",
        "object_id",
        "key_id",
        "provider",
        "key_ref_digest",
        "content_algorithm",
        "wrapping_algorithm",
        "nonce",
        "ciphertext",
        "wrapped_dek",
        "plaintext_digest",
        "aad_digest",
        "created_at",
        "envelope_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise EnvelopeError("Envelope document does not match the strict v1 contract.")
    try:
        return EnvelopeEncryptedArtifact(
            institution_id=document["institution_id"],
            object_type=document["object_type"],
            object_id=document["object_id"],
            key_id=document["key_id"],
            provider=document["provider"],
            key_ref_digest=document["key_ref_digest"],
            content_algorithm=document["content_algorithm"],
            wrapping_algorithm=document["wrapping_algorithm"],
            nonce=document["nonce"],
            ciphertext=document["ciphertext"],
            wrapped_dek=document["wrapped_dek"],
            plaintext_digest=document["plaintext_digest"],
            aad_digest=document["aad_digest"],
            created_at=parse_datetime(document["created_at"]),
            envelope_digest=document["envelope_digest"],
            schema_version=document["schema_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EnvelopeError):
            raise
        raise EnvelopeError(f"Invalid envelope document: {exc}") from exc


def encrypt_bytes(
    plaintext: bytes,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    object_type: str,
    object_id: str,
    created_at: datetime,
) -> EnvelopeEncryptedArtifact:
    if not isinstance(plaintext, bytes):
        raise EnvelopeError("Envelope plaintext must be bytes.")
    if len(plaintext) > 20_000_000:
        raise EnvelopeError("Envelope plaintext exceeds the bounded 20 MB limit.")
    object_type = _validate_text(object_type, "object_type")
    object_id = _validate_text(object_id, "object_id")
    created_at = ensure_aware(created_at)
    key = institution_context.active_key("data_encryption")
    if provider.provider_name != key.provider:
        raise EnvelopeError("Crypto provider does not match the active data-encryption key.")
    key_digest = _key_ref_digest(key.key_ref)
    aad = _aad_document(
        institution_id=institution_context.institution_id,
        object_type=object_type,
        object_id=object_id,
        key_id=key.key_id,
        provider=key.provider,
        key_ref_digest=key_digest,
    )
    aad_bytes = canonical_json(aad).encode("utf-8")
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    try:
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad_bytes)
        wrapped = provider.wrap_data_key(
            key.key_ref,
            dek,
            context=_provider_context(aad),
        )
    except CryptoProviderError as exc:
        raise EnvelopeError("Institution KMS/HSM failed to wrap the envelope DEK.") from exc
    finally:
        # Python cannot guarantee zeroization of every immutable bytes copy.  The
        # DEK is intentionally never persisted and its reference is discarded at
        # the end of this operation.
        del dek
    artifact = EnvelopeEncryptedArtifact(
        institution_id=institution_context.institution_id,
        object_type=object_type,
        object_id=object_id,
        key_id=key.key_id,
        provider=key.provider,
        key_ref_digest=key_digest,
        wrapping_algorithm=wrapped.algorithm,
        nonce=_b64url(nonce),
        ciphertext=_b64url(ciphertext),
        wrapped_dek=_b64url(wrapped.ciphertext),
        plaintext_digest=_sha256_bytes(plaintext),
        aad_digest=_sha256_bytes(aad_bytes),
        created_at=created_at,
    )
    return EnvelopeEncryptedArtifact(**artifact.core(), envelope_digest=artifact.digest())


def decrypt_bytes(
    artifact: EnvelopeEncryptedArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
) -> bytes:
    if artifact.institution_id != institution_context.institution_id:
        raise EnvelopeError("Envelope belongs to a different institution.")
    key = institution_context.key_by_id(artifact.key_id)
    if key.status == "disabled":
        raise EnvelopeError("Envelope key is disabled in the institution context.")
    if key.provider != artifact.provider or provider.provider_name != artifact.provider:
        raise EnvelopeError("Envelope provider binding does not match the institution key.")
    if _key_ref_digest(key.key_ref) != artifact.key_ref_digest:
        raise EnvelopeError("Envelope key reference binding does not match the institution context.")
    aad = _aad_document(
        institution_id=artifact.institution_id,
        object_type=artifact.object_type,
        object_id=artifact.object_id,
        key_id=artifact.key_id,
        provider=artifact.provider,
        key_ref_digest=artifact.key_ref_digest,
    )
    aad_bytes = canonical_json(aad).encode("utf-8")
    if _sha256_bytes(aad_bytes) != artifact.aad_digest:
        raise EnvelopeError("Envelope AAD binding is invalid.")
    wrapped = WrappedDataKey(
        _decode_b64url(artifact.wrapped_dek, name="wrapped_dek", maximum_bytes=16_384),
        artifact.wrapping_algorithm,
    )
    try:
        dek = provider.unwrap_data_key(
            key.key_ref,
            wrapped,
            context=_provider_context(aad),
        )
    except CryptoProviderError as exc:
        raise EnvelopeError("Institution KMS/HSM failed to unwrap the envelope DEK.") from exc
    if not isinstance(dek, bytes) or len(dek) != 32:
        raise EnvelopeError("Institution KMS/HSM returned an invalid envelope DEK.")
    try:
        plaintext = AESGCM(dek).decrypt(
            _decode_b64url(artifact.nonce, name="nonce", maximum_bytes=32),
            _decode_b64url(artifact.ciphertext, name="ciphertext", maximum_bytes=20_000_000),
            aad_bytes,
        )
    except InvalidTag as exc:
        raise EnvelopeError("Envelope ciphertext authentication failed.") from exc
    finally:
        del dek
    if _sha256_bytes(plaintext) != artifact.plaintext_digest:
        raise EnvelopeError("Envelope plaintext digest verification failed.")
    return plaintext


def encrypt_json(
    value: Any,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    object_type: str,
    object_id: str,
    created_at: datetime,
) -> EnvelopeEncryptedArtifact:
    return encrypt_bytes(
        canonical_json(value).encode("utf-8"),
        institution_context=institution_context,
        provider=provider,
        object_type=object_type,
        object_id=object_id,
        created_at=created_at,
    )


def decrypt_json(
    artifact: EnvelopeEncryptedArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
) -> Any:
    plaintext = decrypt_bytes(
        artifact,
        institution_context=institution_context,
        provider=provider,
    )
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("Envelope plaintext is not canonical JSON data.") from exc
