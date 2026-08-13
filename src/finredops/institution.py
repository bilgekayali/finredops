"""Institution security context and provider-neutral key-reference contracts.

The context records institution ownership and opaque KMS/HSM key references.
Secret key material is never stored here.  v0.8.1 cryptographic providers use
these references for real envelope-encryption and signing operations while the
underlying KEKs/private keys remain under institution control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .models import sha256_digest, to_primitive

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_KEY_PURPOSES = frozenset({"data_encryption", "audit_signing", "workload_identity"})
_KEY_PROVIDERS = frozenset(
    {"aws_kms", "azure_key_vault", "gcp_kms", "pkcs11", "external_hsm", "other"}
)
_KEY_STATUSES = frozenset({"active", "retiring", "disabled"})
_SECRET_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "PRIVATE KEY-----",
)


class InstitutionContextError(ValueError):
    """Raised when institution/key-boundary configuration is invalid."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise InstitutionContextError(f"{name} is not a valid bounded identifier.")
    return value


def _text(value: Any, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise InstitutionContextError(f"{name} must be a bounded non-empty string.")
    return value.strip()


@dataclass(frozen=True, slots=True)
class InstitutionKeyReference:
    key_id: str
    purpose: str
    provider: str
    key_ref: str
    status: str = "active"
    institution_owned: bool = True
    public_key_fingerprint: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.key_id, "key_id")
        if self.purpose not in _KEY_PURPOSES:
            raise InstitutionContextError("Unsupported institution key purpose.")
        if self.provider not in _KEY_PROVIDERS:
            raise InstitutionContextError("Unsupported institution key provider.")
        if self.status not in _KEY_STATUSES:
            raise InstitutionContextError("Unsupported institution key status.")
        key_ref = _text(self.key_ref, "key_ref", 1024)
        if any(marker in key_ref.upper() for marker in _SECRET_MARKERS):
            raise InstitutionContextError("key_ref must be an opaque handle, not private key material.")
        if self.institution_owned is not True:
            raise InstitutionContextError("v0.8 institution keys must be institution-owned.")
        if self.public_key_fingerprint is not None and (
            not isinstance(self.public_key_fingerprint, str)
            or not _DIGEST.fullmatch(self.public_key_fingerprint)
        ):
            raise InstitutionContextError(
                "public_key_fingerprint must be a lowercase SHA-256 digest when supplied."
            )

    def as_dict(self) -> dict[str, Any]:
        return to_primitive(self)


@dataclass(frozen=True, slots=True)
class InstitutionSecurityContext:
    institution_id: str
    institution_name: str
    key_references: tuple[InstitutionKeyReference, ...]
    schema_version: str = "finredops.institution-security-context.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "finredops.institution-security-context.v1":
            raise InstitutionContextError("Unsupported institution security context schema.")
        _identifier(self.institution_id, "institution_id")
        _text(self.institution_name, "institution_name", 256)
        if not self.key_references:
            raise InstitutionContextError("At least one institution-owned key reference is required.")
        key_ids = [item.key_id for item in self.key_references]
        if len(set(key_ids)) != len(key_ids):
            raise InstitutionContextError("Institution key ids must be unique.")
        active_counts = {
            purpose: sum(
                1
                for item in self.key_references
                if item.purpose == purpose and item.status == "active"
            )
            for purpose in _KEY_PURPOSES
        }
        ambiguous = sorted(purpose for purpose, count in active_counts.items() if count > 1)
        if ambiguous:
            raise InstitutionContextError(
                "Institution context cannot have multiple active keys for: "
                + ", ".join(ambiguous)
                + "."
            )
        required = {"data_encryption", "audit_signing"}
        missing = sorted(purpose for purpose in required if active_counts[purpose] != 1)
        if missing:
            raise InstitutionContextError(
                "Institution context requires exactly one active key reference for: "
                + ", ".join(missing)
                + "."
            )

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "institution_name": self.institution_name,
            "key_references": [item.as_dict() for item in self.key_references],
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**self.core(), "context_digest": self.digest()}

    def active_key(self, purpose: str) -> InstitutionKeyReference:
        if purpose not in _KEY_PURPOSES:
            raise InstitutionContextError("Unsupported institution key purpose.")
        matches = [
            item
            for item in self.key_references
            if item.purpose == purpose and item.status == "active"
        ]
        if len(matches) != 1:
            raise InstitutionContextError(
                f"Exactly one active institution key is required for purpose {purpose!r}."
            )
        return matches[0]

    def key_by_id(self, key_id: str) -> InstitutionKeyReference:
        _identifier(key_id, "key_id")
        matches = [item for item in self.key_references if item.key_id == key_id]
        if len(matches) != 1:
            raise InstitutionContextError(f"Unknown or ambiguous institution key id {key_id!r}.")
        return matches[0]


def institution_context_from_document(document: Any) -> InstitutionSecurityContext:
    required = {
        "schema_version",
        "institution_id",
        "institution_name",
        "key_references",
        "context_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise InstitutionContextError(
            "Institution security context does not match the v1 contract."
        )
    references_document = document["key_references"]
    if not isinstance(references_document, Sequence) or isinstance(
        references_document, (str, bytes, bytearray)
    ):
        raise InstitutionContextError("key_references must be an array.")
    references: list[InstitutionKeyReference] = []
    reference_fields = {
        "key_id",
        "purpose",
        "provider",
        "key_ref",
        "status",
        "institution_owned",
        "public_key_fingerprint",
    }
    for index, item in enumerate(references_document):
        if not isinstance(item, Mapping) or set(item) != reference_fields:
            raise InstitutionContextError(
                f"key_references[{index}] does not match the v1 contract."
            )
        if not isinstance(item["institution_owned"], bool):
            raise InstitutionContextError(
                f"key_references[{index}].institution_owned must be a boolean."
            )
        references.append(
            InstitutionKeyReference(
                key_id=item["key_id"],
                purpose=item["purpose"],
                provider=item["provider"],
                key_ref=item["key_ref"],
                status=item["status"],
                institution_owned=item["institution_owned"],
                public_key_fingerprint=item["public_key_fingerprint"],
            )
        )
    context = InstitutionSecurityContext(
        institution_id=document["institution_id"],
        institution_name=document["institution_name"],
        key_references=tuple(references),
        schema_version=document["schema_version"],
    )
    if document["context_digest"] != context.digest():
        raise InstitutionContextError("Institution security context digest is invalid.")
    return context


def institution_context_template() -> dict[str, Any]:
    context = InstitutionSecurityContext(
        institution_id="example-bank",
        institution_name="Example Financial Institution",
        key_references=(
            InstitutionKeyReference(
                key_id="data-key-current",
                purpose="data_encryption",
                provider="other",
                key_ref="replace-with-institution-kms-key-reference",
            ),
            InstitutionKeyReference(
                key_id="audit-key-current",
                purpose="audit_signing",
                provider="other",
                key_ref="replace-with-institution-hsm-key-reference",
                public_key_fingerprint=None,
            ),
        ),
    )
    return context.as_dict()
