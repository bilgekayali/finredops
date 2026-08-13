"""Dedicated public-key trust roots for business and report approvals.

Approval keys are intentionally separate from qualified-review trust keys so a
reviewer credential cannot be reused as a business-risk-owner or report-approver
credential. FinRedOps stores public verification material only.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_APPROVAL_ROLES = {"business_risk_owner", "report_approver"}


class ApprovalKeyError(ValueError):
    """Raised when an approval trust bundle violates its strict contract."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ApprovalKeyError(f"{name} is not a valid bounded identifier.")
    return value


def _decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ApprovalKeyError("public_key must be non-empty base64url.")
    try:
        raw = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ApprovalKeyError("public_key is not valid base64url.") from exc
    if len(decoded) != 32:
        raise ApprovalKeyError("public_key must decode to 32 bytes.")
    return decoded


@dataclass(frozen=True, slots=True)
class ApprovalTrustKey:
    issuer: str
    key_id: str
    public_key: str
    roles: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        _identifier(self.issuer, "issuer")
        _identifier(self.key_id, "key_id")
        if self.algorithm != "Ed25519":
            raise ApprovalKeyError("Only Ed25519 approval trust keys are supported.")
        _decode_public_key(self.public_key)
        if not self.roles or any(role not in _APPROVAL_ROLES for role in self.roles):
            raise ApprovalKeyError("Approval trust key roles are invalid.")
        object.__setattr__(self, "roles", tuple(sorted(set(self.roles))))
        start = ensure_aware(self.not_before)
        end = ensure_aware(self.not_after)
        if end <= start:
            raise ApprovalKeyError("Approval trust key validity window is invalid.")
        object.__setattr__(self, "not_before", start)
        object.__setattr__(self, "not_after", end)

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_decode_public_key(self.public_key))


@dataclass(frozen=True, slots=True)
class ApprovalTrustBundle:
    bundle_id: str
    keys: tuple[ApprovalTrustKey, ...]

    def __post_init__(self) -> None:
        _identifier(self.bundle_id, "bundle_id")
        identities = [(item.issuer, item.key_id) for item in self.keys]
        if not self.keys or len(set(identities)) != len(identities):
            raise ApprovalKeyError("Approval trust bundle keys must be non-empty and unique.")

    def digest(self) -> str:
        return sha256_digest(
            {
                "schema_version": "finredops.approval-trust-bundle.v1",
                "bundle_id": self.bundle_id,
                "keys": [to_primitive(item) for item in self.keys],
            }
        )

    def get(self, issuer: str, key_id: str) -> ApprovalTrustKey:
        matches = [item for item in self.keys if item.issuer == issuer and item.key_id == key_id]
        if len(matches) != 1:
            raise ApprovalKeyError("Approval signature references an unknown trust key.")
        return matches[0]


def approval_trust_bundle_from_document(document: Any) -> ApprovalTrustBundle:
    if not isinstance(document, Mapping) or set(document) != {
        "schema_version",
        "bundle_id",
        "keys",
    }:
        raise ApprovalKeyError("Approval trust bundle does not match the v1 contract.")
    if document["schema_version"] != "finredops.approval-trust-bundle.v1":
        raise ApprovalKeyError("Unsupported approval trust bundle schema.")
    raw_keys = document["keys"]
    if not isinstance(raw_keys, list):
        raise ApprovalKeyError("Approval trust bundle keys must be an array.")
    fields = {
        "issuer",
        "key_id",
        "algorithm",
        "public_key",
        "roles",
        "not_before",
        "not_after",
    }
    keys: list[ApprovalTrustKey] = []
    for raw in raw_keys:
        if not isinstance(raw, Mapping) or set(raw) != fields or not isinstance(raw["roles"], list):
            raise ApprovalKeyError("Approval trust key does not match the v1 contract.")
        keys.append(
            ApprovalTrustKey(
                issuer=str(raw["issuer"]),
                key_id=str(raw["key_id"]),
                algorithm=str(raw["algorithm"]),
                public_key=str(raw["public_key"]),
                roles=tuple(str(item) for item in raw["roles"]),
                not_before=parse_datetime(str(raw["not_before"])),
                not_after=parse_datetime(str(raw["not_after"])),
            )
        )
    return ApprovalTrustBundle(str(document["bundle_id"]), tuple(keys))
