"""Independent, verification-only change control for tenant and service-account policy.

FinRedOps never stores change-approver private keys. Two distinct human subjects,
one ``configuration_governor`` and one ``security_governor``, must sign the exact
change-request digest before a production-facing policy or service-account mapping
can be consumed by the guarded CLI paths.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .institution import InstitutionSecurityContext
from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .tenant_auth import TenantRoutingPolicy

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CHANGE_ID = re.compile(r"^FRX-CHG-[A-F0-9]{24}$")
_SIGNATURE_ID = re.compile(r"^FRX-CHS-[A-F0-9]{24}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_CHANGE_ROLES = frozenset({"configuration_governor", "security_governor"})
_CHANGE_TYPES = frozenset({"tenant_routing_policy", "postgres_service_account_mapping"})
_OPERATIONS = frozenset({"create", "update", "disable"})
_KEY_STATUSES = frozenset({"active", "disabled"})
_CLOCK_SKEW_SECONDS = 300
_MAX_REQUEST_WINDOW_SECONDS = 7 * 24 * 60 * 60
_MAX_SIGNATURE_WINDOW_SECONDS = 24 * 60 * 60


class ChangeControlError(ValueError):
    """Raised when signed configuration change control fails closed."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ChangeControlError(f"{name} is not a valid bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ChangeControlError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _optional_digest(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _digest(value, name)


def _text(value: Any, name: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise ChangeControlError(f"{name} must be a bounded non-empty string.")
    return value.strip()


def _decode(value: Any, name: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ChangeControlError(f"{name} must be non-empty base64url.")
    try:
        raw = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ChangeControlError(f"{name} is not valid base64url.") from exc
    if len(decoded) != expected_length:
        raise ChangeControlError(f"{name} must decode to {expected_length} bytes.")
    return decoded


def _canonical(value: Any) -> bytes:
    return json.dumps(
        to_primitive(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _change_id(core: Mapping[str, Any]) -> str:
    return f"FRX-CHG-{sha256_digest(core)[:24].upper()}"


def _signature_id(core: Mapping[str, Any]) -> str:
    return f"FRX-CHS-{sha256_digest(core)[:24].upper()}"


@dataclass(frozen=True, slots=True)
class ChangeTrustKey:
    issuer: str
    key_id: str
    public_key: str
    role: str
    not_before: datetime
    not_after: datetime
    status: str = "active"
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        _identifier(self.issuer, "issuer")
        _identifier(self.key_id, "key_id")
        if self.role not in _CHANGE_ROLES:
            raise ChangeControlError("Change trust key role is unsupported.")
        if self.status not in _KEY_STATUSES:
            raise ChangeControlError("Change trust key status is unsupported.")
        if self.algorithm != "Ed25519":
            raise ChangeControlError("Only Ed25519 change-control trust keys are supported.")
        _decode(self.public_key, "public_key", 32)
        start = ensure_aware(self.not_before)
        end = ensure_aware(self.not_after)
        if end <= start:
            raise ChangeControlError("Change trust key validity window is invalid.")
        object.__setattr__(self, "not_before", start)
        object.__setattr__(self, "not_after", end)

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_decode(self.public_key, "public_key", 32))

    def as_dict(self) -> dict[str, Any]:
        return to_primitive(self)


@dataclass(frozen=True, slots=True)
class ChangeTrustBundle:
    bundle_id: str
    keys: tuple[ChangeTrustKey, ...]
    schema_version: str = "finredops.change-trust-bundle.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "finredops.change-trust-bundle.v1":
            raise ChangeControlError("Unsupported change trust bundle schema.")
        _identifier(self.bundle_id, "bundle_id")
        if not 2 <= len(self.keys) <= 256:
            raise ChangeControlError("Change trust bundle requires 2 to 256 keys.")
        identities = [(item.issuer, item.key_id) for item in self.keys]
        if len(set(identities)) != len(identities):
            raise ChangeControlError("Change trust bundle key identities must be unique.")
        active_roles = {item.role for item in self.keys if item.status == "active"}
        if active_roles != _CHANGE_ROLES:
            raise ChangeControlError(
                "Change trust bundle requires active configuration_governor and security_governor keys."
            )
        object.__setattr__(
            self,
            "keys",
            tuple(sorted(self.keys, key=lambda item: (item.issuer, item.key_id))),
        )

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "keys": [item.as_dict() for item in self.keys],
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def get(self, issuer: str, key_id: str) -> ChangeTrustKey:
        matches = [item for item in self.keys if item.issuer == issuer and item.key_id == key_id]
        if len(matches) != 1:
            raise ChangeControlError("Change signature references an unknown trust key.")
        return matches[0]


def change_trust_bundle_from_document(document: Any) -> ChangeTrustBundle:
    required = {"schema_version", "bundle_id", "keys"}
    if not isinstance(document, Mapping) or set(document) != required:
        raise ChangeControlError("Change trust bundle does not match the v1 contract.")
    if not isinstance(document["keys"], list):
        raise ChangeControlError("Change trust bundle keys must be an array.")
    key_fields = {
        "issuer",
        "key_id",
        "public_key",
        "role",
        "not_before",
        "not_after",
        "status",
        "algorithm",
    }
    keys: list[ChangeTrustKey] = []
    for raw in document["keys"]:
        if not isinstance(raw, Mapping) or set(raw) != key_fields:
            raise ChangeControlError("Change trust key does not match the v1 contract.")
        keys.append(
            ChangeTrustKey(
                issuer=str(raw["issuer"]),
                key_id=str(raw["key_id"]),
                public_key=str(raw["public_key"]),
                role=str(raw["role"]),
                not_before=parse_datetime(str(raw["not_before"])),
                not_after=parse_datetime(str(raw["not_after"])),
                status=str(raw["status"]),
                algorithm=str(raw["algorithm"]),
            )
        )
    return ChangeTrustBundle(
        bundle_id=str(document["bundle_id"]),
        keys=tuple(keys),
        schema_version=str(document["schema_version"]),
    )


@dataclass(frozen=True, slots=True)
class ChangeRequest:
    change_id: str
    institution_id: str
    change_type: str
    operation: str
    object_id: str
    before_digest: str | None
    after_digest: str | None
    context_digest: str
    requested_by: str
    reason: str
    requested_at: datetime
    valid_until: datetime
    schema_version: str = "finredops.change-request.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "finredops.change-request.v1":
            raise ChangeControlError("Unsupported change request schema.")
        if not _CHANGE_ID.fullmatch(self.change_id):
            raise ChangeControlError("Invalid change request id.")
        for name in ("institution_id", "object_id", "requested_by"):
            _identifier(getattr(self, name), name)
        if self.change_type not in _CHANGE_TYPES:
            raise ChangeControlError("Unsupported configuration change type.")
        if self.operation not in _OPERATIONS:
            raise ChangeControlError("Unsupported configuration change operation.")
        before = _optional_digest(self.before_digest, "before_digest")
        after = _optional_digest(self.after_digest, "after_digest")
        _digest(self.context_digest, "context_digest")
        object.__setattr__(self, "reason", _text(self.reason, "reason", 1024))
        requested = ensure_aware(self.requested_at)
        deadline = ensure_aware(self.valid_until)
        seconds = (deadline - requested).total_seconds()
        if seconds <= 0 or seconds > _MAX_REQUEST_WINDOW_SECONDS:
            raise ChangeControlError("Change request validity must be >0 and <=7 days.")
        if self.operation == "create" and (before is not None or after is None):
            raise ChangeControlError("Create changes require after_digest and no before_digest.")
        if self.operation == "update" and (
            before is None or after is None or before == after
        ):
            raise ChangeControlError("Update changes require distinct before/after digests.")
        if self.operation == "disable" and (before is None or after is not None):
            raise ChangeControlError("Disable changes require before_digest and no after_digest.")
        object.__setattr__(self, "requested_at", requested)
        object.__setattr__(self, "valid_until", deadline)
        if self.change_id != _change_id(self.core_without_id()):
            raise ChangeControlError("Change request id does not match its payload.")

    def core_without_id(self) -> dict[str, Any]:
        return {
            "institution_id": self.institution_id,
            "change_type": self.change_type,
            "operation": self.operation,
            "object_id": self.object_id,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "context_digest": self.context_digest,
            "requested_by": self.requested_by,
            "reason": self.reason,
            "requested_at": self.requested_at,
            "valid_until": self.valid_until,
        }

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "change_id": self.change_id,
            **self.core_without_id(),
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.core()), "request_digest": self.digest()}


def build_change_request(
    *,
    institution_id: str,
    change_type: str,
    operation: str,
    object_id: str,
    before_digest: str | None,
    after_digest: str | None,
    context_digest: str,
    requested_by: str,
    reason: str,
    requested_at: datetime,
    valid_until: datetime,
) -> ChangeRequest:
    body = {
        "institution_id": institution_id,
        "change_type": change_type,
        "operation": operation,
        "object_id": object_id,
        "before_digest": before_digest,
        "after_digest": after_digest,
        "context_digest": context_digest,
        "requested_by": requested_by,
        "reason": reason,
        "requested_at": ensure_aware(requested_at),
        "valid_until": ensure_aware(valid_until),
    }
    return ChangeRequest(change_id=_change_id(body), **body)


def change_request_from_document(document: Any) -> ChangeRequest:
    required = {
        "schema_version",
        "change_id",
        "institution_id",
        "change_type",
        "operation",
        "object_id",
        "before_digest",
        "after_digest",
        "context_digest",
        "requested_by",
        "reason",
        "requested_at",
        "valid_until",
        "request_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ChangeControlError("Change request does not match the v1 contract.")
    request = ChangeRequest(
        change_id=str(document["change_id"]),
        institution_id=str(document["institution_id"]),
        change_type=str(document["change_type"]),
        operation=str(document["operation"]),
        object_id=str(document["object_id"]),
        before_digest=(None if document["before_digest"] is None else str(document["before_digest"])),
        after_digest=(None if document["after_digest"] is None else str(document["after_digest"])),
        context_digest=str(document["context_digest"]),
        requested_by=str(document["requested_by"]),
        reason=str(document["reason"]),
        requested_at=parse_datetime(str(document["requested_at"])),
        valid_until=parse_datetime(str(document["valid_until"])),
        schema_version=str(document["schema_version"]),
    )
    if document["request_digest"] != request.digest():
        raise ChangeControlError("Change request digest is invalid.")
    return request


@dataclass(frozen=True, slots=True)
class ChangeSignature:
    signature_id: str
    issuer: str
    subject: str
    key_id: str
    role: str
    institution_id: str
    change_id: str
    request_digest: str
    issued_at: datetime
    expires_at: datetime
    signature: str
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        if not _SIGNATURE_ID.fullmatch(self.signature_id):
            raise ChangeControlError("Invalid change signature id.")
        for name in ("issuer", "subject", "key_id", "institution_id"):
            _identifier(getattr(self, name), name)
        if self.role not in _CHANGE_ROLES:
            raise ChangeControlError("Unsupported change signature role.")
        if not _CHANGE_ID.fullmatch(self.change_id):
            raise ChangeControlError("Invalid signed change request id.")
        _digest(self.request_digest, "request_digest")
        if self.algorithm != "Ed25519":
            raise ChangeControlError("Only Ed25519 change signatures are supported.")
        issued = ensure_aware(self.issued_at)
        expires = ensure_aware(self.expires_at)
        seconds = (expires - issued).total_seconds()
        if seconds <= 0 or seconds > _MAX_SIGNATURE_WINDOW_SECONDS:
            raise ChangeControlError("Change signature validity must be >0 and <=24 hours.")
        _decode(self.signature, "signature", 64)
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        if self.signature_id != _signature_id(self.core()):
            raise ChangeControlError("Change signature id does not match its payload.")

    def core(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "role": self.role,
            "institution_id": self.institution_id,
            "change_id": self.change_id,
            "request_digest": self.request_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.change-signature.v1",
            "signature_id": self.signature_id,
            **to_primitive(self.core()),
        }

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_document())

    def as_dict(self) -> dict[str, Any]:
        return {**self.signing_document(), "signature": self.signature}


def change_signature_request(
    request: ChangeRequest,
    *,
    issuer: str,
    subject: str,
    key_id: str,
    role: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    core = {
        "issuer": issuer,
        "subject": subject,
        "key_id": key_id,
        "algorithm": "Ed25519",
        "role": role,
        "institution_id": request.institution_id,
        "change_id": request.change_id,
        "request_digest": request.digest(),
        "issued_at": ensure_aware(issued_at),
        "expires_at": ensure_aware(expires_at),
    }
    probe = ChangeSignature(
        signature_id=_signature_id(core),
        signature=base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("="),
        **core,
    )
    if probe.issued_at < request.requested_at or probe.issued_at > request.valid_until:
        raise ChangeControlError("Change signature issuance must fall within the request window.")
    if probe.expires_at > request.valid_until + __import__("datetime").timedelta(seconds=_CLOCK_SKEW_SECONDS):
        raise ChangeControlError("Change signature expiry exceeds the request approval window.")
    return probe.signing_document()


def finalize_change_signature(signing_request: Any, signature: str) -> ChangeSignature:
    required = {
        "schema_version",
        "signature_id",
        "issuer",
        "subject",
        "key_id",
        "algorithm",
        "role",
        "institution_id",
        "change_id",
        "request_digest",
        "issued_at",
        "expires_at",
    }
    if not isinstance(signing_request, Mapping) or set(signing_request) != required:
        raise ChangeControlError("Change signing request does not match the v1 contract.")
    if signing_request["schema_version"] != "finredops.change-signature.v1":
        raise ChangeControlError("Unsupported change signing request schema.")
    return ChangeSignature(
        signature_id=str(signing_request["signature_id"]),
        issuer=str(signing_request["issuer"]),
        subject=str(signing_request["subject"]),
        key_id=str(signing_request["key_id"]),
        algorithm=str(signing_request["algorithm"]),
        role=str(signing_request["role"]),
        institution_id=str(signing_request["institution_id"]),
        change_id=str(signing_request["change_id"]),
        request_digest=str(signing_request["request_digest"]),
        issued_at=parse_datetime(str(signing_request["issued_at"])),
        expires_at=parse_datetime(str(signing_request["expires_at"])),
        signature=signature.strip(),
    )


def change_signature_from_document(document: Any) -> ChangeSignature:
    if not isinstance(document, Mapping) or "signature" not in document:
        raise ChangeControlError("Change signature does not match the v1 contract.")
    signing = {key: value for key, value in document.items() if key != "signature"}
    return finalize_change_signature(signing, str(document["signature"]))


def _verify_change_signature(
    signature: ChangeSignature,
    request: ChangeRequest,
    bundle: ChangeTrustBundle,
    *,
    as_of: datetime,
) -> None:
    effective = ensure_aware(as_of)
    key = bundle.get(signature.issuer, signature.key_id)
    checks = (
        (key.status == "active", "trust-key status"),
        (key.role == signature.role, "role"),
        (key.algorithm == signature.algorithm, "algorithm"),
        (signature.institution_id == request.institution_id, "institution"),
        (signature.change_id == request.change_id, "change-id"),
        (signature.request_digest == request.digest(), "request-digest"),
        (request.requested_at <= effective <= request.valid_until, "request-window"),
        (key.not_before <= effective <= key.not_after, "trust-key validity"),
        (
            effective.timestamp() + _CLOCK_SKEW_SECONDS >= signature.issued_at.timestamp(),
            "signature-not-before",
        ),
        (
            effective.timestamp() - _CLOCK_SKEW_SECONDS <= signature.expires_at.timestamp(),
            "signature-expiry",
        ),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ChangeControlError(f"Change signature binding failed: {', '.join(failed)}.")
    try:
        key.verifier().verify(
            _decode(signature.signature, "signature", 64),
            signature.signing_bytes(),
        )
    except InvalidSignature as exc:
        raise ChangeControlError("Change signature verification failed.") from exc


@dataclass(frozen=True, slots=True)
class ChangeControlResolution:
    change_id: str
    request_digest: str
    trust_bundle_digest: str
    signature_ids: tuple[str, ...]
    subjects: tuple[str, ...]
    roles: tuple[str, ...]
    approved_at: datetime

    def __post_init__(self) -> None:
        if not _CHANGE_ID.fullmatch(self.change_id):
            raise ChangeControlError("Invalid resolved change id.")
        _digest(self.request_digest, "request_digest")
        _digest(self.trust_bundle_digest, "trust_bundle_digest")
        if len(self.signature_ids) != 2 or len(set(self.signature_ids)) != 2:
            raise ChangeControlError("Change resolution requires exactly two unique signatures.")
        if len(self.subjects) != 2 or len(set(self.subjects)) != 2:
            raise ChangeControlError("Change resolution requires two distinct human subjects.")
        if set(self.roles) != _CHANGE_ROLES or len(self.roles) != 2:
            raise ChangeControlError("Change resolution requires both independent governor roles.")
        object.__setattr__(self, "signature_ids", tuple(sorted(self.signature_ids)))
        object.__setattr__(self, "subjects", tuple(sorted(self.subjects)))
        object.__setattr__(self, "roles", tuple(sorted(self.roles)))
        object.__setattr__(self, "approved_at", ensure_aware(self.approved_at))

    def body(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.change-control-resolution.v1",
            "change_id": self.change_id,
            "request_digest": self.request_digest,
            "trust_bundle_digest": self.trust_bundle_digest,
            "signature_ids": list(self.signature_ids),
            "subjects": list(self.subjects),
            "roles": list(self.roles),
            "approved_at": self.approved_at,
            "cryptographic_signatures_verified": True,
            "independent_change_approval_verified": True,
            "signature_algorithm": "Ed25519",
        }

    def as_dict(self) -> dict[str, Any]:
        body = to_primitive(self.body())
        return {**body, "resolution_digest": sha256_digest(body)}


def change_control_resolution_from_document(document: Any) -> ChangeControlResolution:
    required = {
        "schema_version",
        "change_id",
        "request_digest",
        "trust_bundle_digest",
        "signature_ids",
        "subjects",
        "roles",
        "approved_at",
        "cryptographic_signatures_verified",
        "independent_change_approval_verified",
        "signature_algorithm",
        "resolution_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ChangeControlError("Change-control resolution does not match the v1 contract.")
    if (
        document["schema_version"] != "finredops.change-control-resolution.v1"
        or document["cryptographic_signatures_verified"] is not True
        or document["independent_change_approval_verified"] is not True
        or document["signature_algorithm"] != "Ed25519"
        or not isinstance(document["signature_ids"], list)
        or not isinstance(document["subjects"], list)
        or not isinstance(document["roles"], list)
    ):
        raise ChangeControlError("Change-control resolution safety markers are invalid.")
    resolution = ChangeControlResolution(
        change_id=str(document["change_id"]),
        request_digest=str(document["request_digest"]),
        trust_bundle_digest=str(document["trust_bundle_digest"]),
        signature_ids=tuple(str(item) for item in document["signature_ids"]),
        subjects=tuple(str(item) for item in document["subjects"]),
        roles=tuple(str(item) for item in document["roles"]),
        approved_at=parse_datetime(str(document["approved_at"])),
    )
    if document["resolution_digest"] != resolution.as_dict()["resolution_digest"]:
        raise ChangeControlError("Change-control resolution digest is invalid.")
    return resolution


def resolve_change_control(
    request: ChangeRequest,
    signatures: Sequence[ChangeSignature],
    bundle: ChangeTrustBundle,
    *,
    approved_at: datetime,
) -> ChangeControlResolution:
    effective = ensure_aware(approved_at)
    if len(signatures) != 2:
        raise ChangeControlError("Exactly two change signatures are required.")
    ids = [item.signature_id for item in signatures]
    identities = [(item.issuer, item.key_id) for item in signatures]
    subjects = [item.subject for item in signatures]
    roles = [item.role for item in signatures]
    if len(set(ids)) != 2 or len(set(identities)) != 2:
        raise ChangeControlError("Change signatures must use two distinct trust keys.")
    if len(set(subjects)) != 2:
        raise ChangeControlError("Change approvals require two distinct human subjects.")
    if set(roles) != _CHANGE_ROLES or len(roles) != 2:
        raise ChangeControlError("Change approvals require one signature from each governor role.")
    for signature in signatures:
        _verify_change_signature(signature, request, bundle, as_of=effective)
    return ChangeControlResolution(
        change_id=request.change_id,
        request_digest=request.digest(),
        trust_bundle_digest=bundle.digest(),
        signature_ids=tuple(ids),
        subjects=tuple(subjects),
        roles=tuple(roles),
        approved_at=effective,
    )


def approved_change_package(
    request: ChangeRequest,
    signatures: Sequence[ChangeSignature],
    bundle: ChangeTrustBundle,
    *,
    approved_at: datetime,
) -> dict[str, Any]:
    resolution = resolve_change_control(request, signatures, bundle, approved_at=approved_at)
    body = {
        "schema_version": "finredops.approved-change-package.v1",
        "change_request": request.as_dict(),
        "signatures": [item.as_dict() for item in sorted(signatures, key=lambda item: item.signature_id)],
        "resolution": resolution.as_dict(),
        "change_authorized": True,
    }
    return {**body, "package_digest": sha256_digest(body)}


def verify_approved_change_package(
    document: Any,
    bundle: ChangeTrustBundle,
) -> ChangeRequest:
    required = {
        "schema_version",
        "change_request",
        "signatures",
        "resolution",
        "change_authorized",
        "package_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ChangeControlError("Approved change package does not match the v1 contract.")
    if document["schema_version"] != "finredops.approved-change-package.v1" or document["change_authorized"] is not True:
        raise ChangeControlError("Approved change package safety markers are invalid.")
    body = {key: document[key] for key in required if key != "package_digest"}
    if document["package_digest"] != sha256_digest(body):
        raise ChangeControlError("Approved change package digest is invalid.")
    if not isinstance(document["signatures"], list) or len(document["signatures"]) != 2:
        raise ChangeControlError("Approved change package requires exactly two signatures.")
    request = change_request_from_document(document["change_request"])
    signatures = tuple(change_signature_from_document(item) for item in document["signatures"])
    resolution = change_control_resolution_from_document(document["resolution"])
    if resolution.trust_bundle_digest != bundle.digest():
        raise ChangeControlError("Approved change package references a different trust bundle.")
    reproduced = resolve_change_control(
        request,
        signatures,
        bundle,
        approved_at=resolution.approved_at,
    )
    if reproduced.as_dict() != resolution.as_dict():
        raise ChangeControlError("Approved change package resolution is not reproducible.")
    return request


def tenant_policy_change_request(
    policy: TenantRoutingPolicy,
    context: InstitutionSecurityContext,
    *,
    operation: str,
    prior_policy_digest: str | None,
    requested_by: str,
    reason: str,
    requested_at: datetime,
    valid_until: datetime,
) -> ChangeRequest:
    if policy.institution_id != context.institution_id:
        raise ChangeControlError("Tenant policy and institution context do not match.")
    if operation not in {"create", "update"}:
        raise ChangeControlError("Tenant policy approval supports create or update operations.")
    return build_change_request(
        institution_id=policy.institution_id,
        change_type="tenant_routing_policy",
        operation=operation,
        object_id=policy.policy_id,
        before_digest=prior_policy_digest,
        after_digest=policy.digest(),
        context_digest=context.digest(),
        requested_by=requested_by,
        reason=reason,
        requested_at=requested_at,
        valid_until=valid_until,
    )


def verify_tenant_policy_change_package(
    policy: TenantRoutingPolicy,
    context: InstitutionSecurityContext,
    package: Any,
    bundle: ChangeTrustBundle,
) -> ChangeRequest:
    request = verify_approved_change_package(package, bundle)
    checks = (
        (request.change_type == "tenant_routing_policy", "change-type"),
        (request.operation in {"create", "update"}, "operation"),
        (request.institution_id == policy.institution_id == context.institution_id, "institution"),
        (request.object_id == policy.policy_id, "policy-id"),
        (request.after_digest == policy.digest(), "policy-digest"),
        (request.context_digest == context.digest(), "institution-context"),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ChangeControlError(f"Tenant policy change package binding failed: {', '.join(failed)}.")
    return request


@dataclass(frozen=True, slots=True)
class PostgresServiceAccountChange:
    service_role: str
    institution_id: str
    access_mode: str
    contract_digest: str
    schema_version: str = "finredops.postgres-service-account-change.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "finredops.postgres-service-account-change.v1":
            raise ChangeControlError("Unsupported PostgreSQL service-account change schema.")
        _identifier(self.service_role, "service_role")
        _identifier(self.institution_id, "institution_id")
        if self.access_mode not in {"read", "write"}:
            raise ChangeControlError("PostgreSQL service-account access mode must be read or write.")
        _digest(self.contract_digest, "contract_digest")

    def body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "service_role": self.service_role,
            "institution_id": self.institution_id,
            "access_mode": self.access_mode,
            "contract_digest": self.contract_digest,
        }

    def digest(self) -> str:
        return sha256_digest(self.body())

    def as_dict(self) -> dict[str, Any]:
        return {**self.body(), "mapping_digest": self.digest()}


def postgres_service_account_change_from_document(document: Any) -> PostgresServiceAccountChange:
    required = {
        "schema_version",
        "service_role",
        "institution_id",
        "access_mode",
        "contract_digest",
        "mapping_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ChangeControlError("PostgreSQL service-account change does not match the v1 contract.")
    change = PostgresServiceAccountChange(
        service_role=str(document["service_role"]),
        institution_id=str(document["institution_id"]),
        access_mode=str(document["access_mode"]),
        contract_digest=str(document["contract_digest"]),
        schema_version=str(document["schema_version"]),
    )
    if document["mapping_digest"] != change.digest():
        raise ChangeControlError("PostgreSQL service-account mapping digest is invalid.")
    return change


def postgres_service_account_change_request(
    change: PostgresServiceAccountChange,
    *,
    operation: str,
    prior_mapping_digest: str | None,
    requested_by: str,
    reason: str,
    requested_at: datetime,
    valid_until: datetime,
) -> ChangeRequest:
    if operation not in {"create", "update"}:
        raise ChangeControlError("Service-account mapping approval supports create or update operations.")
    return build_change_request(
        institution_id=change.institution_id,
        change_type="postgres_service_account_mapping",
        operation=operation,
        object_id=change.service_role,
        before_digest=prior_mapping_digest,
        after_digest=change.digest(),
        context_digest=change.contract_digest,
        requested_by=requested_by,
        reason=reason,
        requested_at=requested_at,
        valid_until=valid_until,
    )


def postgres_service_account_disable_request(
    *,
    service_role: str,
    institution_id: str,
    contract_digest: str,
    prior_mapping_digest: str,
    requested_by: str,
    reason: str,
    requested_at: datetime,
    valid_until: datetime,
) -> ChangeRequest:
    return build_change_request(
        institution_id=institution_id,
        change_type="postgres_service_account_mapping",
        operation="disable",
        object_id=service_role,
        before_digest=prior_mapping_digest,
        after_digest=None,
        context_digest=contract_digest,
        requested_by=requested_by,
        reason=reason,
        requested_at=requested_at,
        valid_until=valid_until,
    )


def verify_postgres_mapping_change_package(
    change: PostgresServiceAccountChange,
    package: Any,
    bundle: ChangeTrustBundle,
) -> ChangeRequest:
    request = verify_approved_change_package(package, bundle)
    checks = (
        (request.change_type == "postgres_service_account_mapping", "change-type"),
        (request.operation in {"create", "update"}, "operation"),
        (request.institution_id == change.institution_id, "institution"),
        (request.object_id == change.service_role, "service-role"),
        (request.after_digest == change.digest(), "mapping-digest"),
        (request.context_digest == change.contract_digest, "contract-digest"),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ChangeControlError(f"Service-account change package binding failed: {', '.join(failed)}.")
    return request


def verify_postgres_disable_change_package(
    *,
    service_role: str,
    institution_id: str,
    contract_digest: str,
    package: Any,
    bundle: ChangeTrustBundle,
) -> ChangeRequest:
    request = verify_approved_change_package(package, bundle)
    checks = (
        (request.change_type == "postgres_service_account_mapping", "change-type"),
        (request.operation == "disable", "operation"),
        (request.institution_id == institution_id, "institution"),
        (request.object_id == service_role, "service-role"),
        (request.before_digest is not None and request.after_digest is None, "mapping-state"),
        (request.context_digest == contract_digest, "contract-digest"),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ChangeControlError(f"Service-account disable package binding failed: {', '.join(failed)}.")
    return request
