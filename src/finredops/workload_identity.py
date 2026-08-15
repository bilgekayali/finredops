"""Institution-owned signed workload identity for isolated execution providers.

The control plane verifies workload identity using the institution security
context and an injected KMS/HSM provider. Private signing keys and workload
credentials are never stored in these artifacts.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Mapping

from .crypto_provider import CryptoProviderError, KmsHsmProvider, ProviderSignature
from .institution import InstitutionContextError, InstitutionSecurityContext
from .models import canonical_json, ensure_aware, parse_datetime, sha256_digest, to_primitive

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_ATTESTATION_SCHEMA = "finredops.workload-identity-attestation.v1"
_RECEIPT_SIGNATURE_SCHEMA = "finredops.worker-receipt-signature.v1"


class WorkloadIdentityError(ValueError):
    """Raised when workload identity/signature verification fails closed."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WorkloadIdentityError(f"{name} must be a bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise WorkloadIdentityError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise WorkloadIdentityError(f"{name} must be bounded printable text.")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise WorkloadIdentityError("Signature must be bounded base64url text.")
    try:
        raw = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception as exc:
        raise WorkloadIdentityError("Signature is not valid base64url data.") from exc
    if not raw or len(raw) > 8_192 or _b64url(raw) != value:
        raise WorkloadIdentityError("Signature is not canonical bounded base64url data.")
    return raw


def _key_ref_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_digest(document: Mapping[str, Any]) -> tuple[str, bytes]:
    encoded = canonical_json(document).encode("utf-8")
    raw = hashlib.sha256(encoded).digest()
    return raw.hex(), raw


def _workload_key(context: InstitutionSecurityContext, key_id: str | None = None):
    try:
        key = context.active_key("workload_identity") if key_id is None else context.key_by_id(key_id)
    except InstitutionContextError as exc:
        raise WorkloadIdentityError("Institution workload-identity key is unavailable.") from exc
    if key.purpose != "workload_identity":
        raise WorkloadIdentityError("Selected institution key is not a workload-identity key.")
    return key


@dataclass(frozen=True, slots=True)
class WorkloadIdentityAttestation:
    institution_id: str
    worker_id: str
    deployment_id: str
    isolation_profile: str
    runtime_image_digest: str
    network_policy_digest: str
    isolation_evidence_digest: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    provider: str
    key_ref_digest: str
    signing_algorithm: str
    signature: str
    signing_document_digest: str
    artifact_digest: str = ""
    schema_version: str = _ATTESTATION_SCHEMA
    control_plane_embedded: bool = False
    private_key_embedded: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != _ATTESTATION_SCHEMA:
            raise WorkloadIdentityError("Unsupported workload identity schema.")
        for value, name in (
            (self.institution_id, "institution_id"),
            (self.worker_id, "worker_id"),
            (self.deployment_id, "deployment_id"),
            (self.key_id, "key_id"),
        ):
            _identifier(value, name)
        for value, name in (
            (self.isolation_profile, "isolation_profile"),
            (self.provider, "provider"),
            (self.signing_algorithm, "signing_algorithm"),
        ):
            _text(value, name)
        for value, name in (
            (self.runtime_image_digest, "runtime_image_digest"),
            (self.network_policy_digest, "network_policy_digest"),
            (self.isolation_evidence_digest, "isolation_evidence_digest"),
            (self.key_ref_digest, "key_ref_digest"),
            (self.signing_document_digest, "signing_document_digest"),
        ):
            _digest(value, name)
        issued = ensure_aware(self.issued_at)
        expires = ensure_aware(self.expires_at)
        if expires <= issued:
            raise WorkloadIdentityError("Workload identity expiry must follow issuance.")
        if (expires - issued).total_seconds() > 3_600:
            raise WorkloadIdentityError("Workload identity lifetime cannot exceed one hour.")
        if self.control_plane_embedded is not False or self.private_key_embedded is not False:
            raise WorkloadIdentityError("Workload identity must remain external and keyless to the control plane.")
        _decode_b64url(self.signature)
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        if self.artifact_digest:
            _digest(self.artifact_digest, "artifact_digest")
            if self.artifact_digest != self.digest():
                raise WorkloadIdentityError("Workload identity artifact digest is invalid.")

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.workload-identity-signing-document.v1",
            "institution_id": self.institution_id,
            "worker_id": self.worker_id,
            "deployment_id": self.deployment_id,
            "isolation_profile": self.isolation_profile,
            "runtime_image_digest": self.runtime_image_digest,
            "network_policy_digest": self.network_policy_digest,
            "isolation_evidence_digest": self.isolation_evidence_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "provider": self.provider,
            "key_ref_digest": self.key_ref_digest,
            "control_plane_embedded": False,
            "private_key_embedded": False,
        }

    def core(self) -> dict[str, Any]:
        document = self.signing_document()
        document["schema_version"] = self.schema_version
        return {
            **document,
            "signing_algorithm": self.signing_algorithm,
            "signature": self.signature,
            "signing_document_digest": self.signing_document_digest,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "artifact_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class WorkerReceiptSignature:
    institution_id: str
    worker_id: str
    execution_id: str
    execution_envelope_digest: str
    workload_identity_digest: str
    lease_digest: str
    signed_at: datetime
    key_id: str
    provider: str
    key_ref_digest: str
    signing_algorithm: str
    signature: str
    signing_document_digest: str
    artifact_digest: str = ""
    schema_version: str = _RECEIPT_SIGNATURE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _RECEIPT_SIGNATURE_SCHEMA:
            raise WorkloadIdentityError("Unsupported worker receipt signature schema.")
        for value, name in (
            (self.institution_id, "institution_id"),
            (self.worker_id, "worker_id"),
            (self.execution_id, "execution_id"),
            (self.key_id, "key_id"),
        ):
            _identifier(value, name)
        for value, name in ((self.provider, "provider"), (self.signing_algorithm, "signing_algorithm")):
            _text(value, name)
        for value, name in (
            (self.execution_envelope_digest, "execution_envelope_digest"),
            (self.workload_identity_digest, "workload_identity_digest"),
            (self.lease_digest, "lease_digest"),
            (self.key_ref_digest, "key_ref_digest"),
            (self.signing_document_digest, "signing_document_digest"),
        ):
            _digest(value, name)
        object.__setattr__(self, "signed_at", ensure_aware(self.signed_at))
        _decode_b64url(self.signature)
        if self.artifact_digest:
            _digest(self.artifact_digest, "artifact_digest")
            if self.artifact_digest != self.digest():
                raise WorkloadIdentityError("Worker receipt signature digest is invalid.")

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.worker-receipt-signing-document.v1",
            "institution_id": self.institution_id,
            "worker_id": self.worker_id,
            "execution_id": self.execution_id,
            "execution_envelope_digest": self.execution_envelope_digest,
            "workload_identity_digest": self.workload_identity_digest,
            "lease_digest": self.lease_digest,
            "signed_at": self.signed_at,
            "key_id": self.key_id,
            "provider": self.provider,
            "key_ref_digest": self.key_ref_digest,
        }

    def core(self) -> dict[str, Any]:
        document = self.signing_document()
        document["schema_version"] = self.schema_version
        return {
            **document,
            "signing_algorithm": self.signing_algorithm,
            "signature": self.signature,
            "signing_document_digest": self.signing_document_digest,
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "artifact_digest": self.digest()}


def create_workload_identity_attestation(
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    worker_id: str,
    deployment_id: str,
    isolation_profile: str,
    runtime_image_digest: str,
    network_policy_digest: str,
    isolation_evidence_digest: str,
    issued_at: datetime,
    expires_at: datetime,
) -> WorkloadIdentityAttestation:
    key = _workload_key(institution_context)
    if provider.provider_name != key.provider:
        raise WorkloadIdentityError("Crypto provider does not match the active workload key.")
    prototype = WorkloadIdentityAttestation(
        institution_id=institution_context.institution_id,
        worker_id=worker_id,
        deployment_id=deployment_id,
        isolation_profile=isolation_profile,
        runtime_image_digest=runtime_image_digest,
        network_policy_digest=network_policy_digest,
        isolation_evidence_digest=isolation_evidence_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=key.key_id,
        provider=key.provider,
        key_ref_digest=_key_ref_digest(key.key_ref),
        signing_algorithm="PENDING",
        signature="AA",
        signing_document_digest="0" * 64,
    )
    signing_document_digest, raw_digest = _document_digest(prototype.signing_document())
    try:
        produced = provider.sign_digest(key.key_ref, raw_digest)
    except CryptoProviderError as exc:
        raise WorkloadIdentityError("Institution KMS/HSM could not sign workload identity.") from exc
    artifact = replace(
        prototype,
        signing_algorithm=produced.algorithm,
        signature=_b64url(produced.signature),
        signing_document_digest=signing_document_digest,
    )
    return replace(artifact, artifact_digest=artifact.digest())


def verify_workload_identity_attestation(
    artifact: WorkloadIdentityAttestation,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    as_of: datetime,
) -> bool:
    now = ensure_aware(as_of)
    if artifact.institution_id != institution_context.institution_id:
        return False
    if not artifact.issued_at <= now < artifact.expires_at:
        return False
    try:
        key = _workload_key(institution_context, artifact.key_id)
    except WorkloadIdentityError:
        return False
    if key.status == "disabled" or key.provider != artifact.provider or provider.provider_name != artifact.provider:
        return False
    if _key_ref_digest(key.key_ref) != artifact.key_ref_digest:
        return False
    document_digest, raw_digest = _document_digest(artifact.signing_document())
    if document_digest != artifact.signing_document_digest:
        return False
    try:
        return provider.verify_digest(
            key.key_ref,
            raw_digest,
            ProviderSignature(_decode_b64url(artifact.signature), artifact.signing_algorithm),
        )
    except CryptoProviderError:
        return False


def sign_worker_receipt(
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    identity: WorkloadIdentityAttestation,
    execution_id: str,
    execution_envelope_digest: str,
    lease_digest: str,
    signed_at: datetime,
) -> WorkerReceiptSignature:
    key = _workload_key(institution_context, identity.key_id)
    if provider.provider_name != key.provider or identity.institution_id != institution_context.institution_id:
        raise WorkloadIdentityError("Worker receipt signer does not match workload identity.")
    prototype = WorkerReceiptSignature(
        institution_id=institution_context.institution_id,
        worker_id=identity.worker_id,
        execution_id=execution_id,
        execution_envelope_digest=execution_envelope_digest,
        workload_identity_digest=identity.digest(),
        lease_digest=lease_digest,
        signed_at=signed_at,
        key_id=key.key_id,
        provider=key.provider,
        key_ref_digest=_key_ref_digest(key.key_ref),
        signing_algorithm="PENDING",
        signature="AA",
        signing_document_digest="0" * 64,
    )
    signing_document_digest, raw_digest = _document_digest(prototype.signing_document())
    try:
        produced = provider.sign_digest(key.key_ref, raw_digest)
    except CryptoProviderError as exc:
        raise WorkloadIdentityError("Institution KMS/HSM could not sign worker receipt.") from exc
    artifact = replace(
        prototype,
        signing_algorithm=produced.algorithm,
        signature=_b64url(produced.signature),
        signing_document_digest=signing_document_digest,
    )
    return replace(artifact, artifact_digest=artifact.digest())


def verify_worker_receipt_signature(
    artifact: WorkerReceiptSignature,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
    identity: WorkloadIdentityAttestation,
    execution_id: str,
    execution_envelope_digest: str,
    lease_digest: str,
) -> bool:
    if (
        artifact.institution_id != institution_context.institution_id
        or artifact.worker_id != identity.worker_id
        or artifact.execution_id != execution_id
        or artifact.execution_envelope_digest != execution_envelope_digest
        or artifact.workload_identity_digest != identity.digest()
        or artifact.lease_digest != lease_digest
    ):
        return False
    try:
        key = _workload_key(institution_context, artifact.key_id)
    except WorkloadIdentityError:
        return False
    if key.status == "disabled" or key.provider != artifact.provider or provider.provider_name != artifact.provider:
        return False
    if _key_ref_digest(key.key_ref) != artifact.key_ref_digest:
        return False
    document_digest, raw_digest = _document_digest(artifact.signing_document())
    if document_digest != artifact.signing_document_digest:
        return False
    try:
        return provider.verify_digest(
            key.key_ref,
            raw_digest,
            ProviderSignature(_decode_b64url(artifact.signature), artifact.signing_algorithm),
        )
    except CryptoProviderError:
        return False


def workload_identity_from_document(document: Any) -> WorkloadIdentityAttestation:
    if not isinstance(document, Mapping):
        raise WorkloadIdentityError("Workload identity artifact must be an object.")
    expected = {
        "schema_version", "institution_id", "worker_id", "deployment_id", "isolation_profile",
        "runtime_image_digest", "network_policy_digest", "isolation_evidence_digest", "issued_at",
        "expires_at", "key_id", "provider", "key_ref_digest", "signing_algorithm", "signature",
        "signing_document_digest", "artifact_digest", "control_plane_embedded", "private_key_embedded",
    }
    if set(document) != expected:
        raise WorkloadIdentityError("Workload identity artifact does not match the strict v1 contract.")
    return WorkloadIdentityAttestation(
        institution_id=document["institution_id"],
        worker_id=document["worker_id"],
        deployment_id=document["deployment_id"],
        isolation_profile=document["isolation_profile"],
        runtime_image_digest=document["runtime_image_digest"],
        network_policy_digest=document["network_policy_digest"],
        isolation_evidence_digest=document["isolation_evidence_digest"],
        issued_at=parse_datetime(document["issued_at"]),
        expires_at=parse_datetime(document["expires_at"]),
        key_id=document["key_id"],
        provider=document["provider"],
        key_ref_digest=document["key_ref_digest"],
        signing_algorithm=document["signing_algorithm"],
        signature=document["signature"],
        signing_document_digest=document["signing_document_digest"],
        artifact_digest=document["artifact_digest"],
        schema_version=document["schema_version"],
        control_plane_embedded=document["control_plane_embedded"],
        private_key_embedded=document["private_key_embedded"],
    )
