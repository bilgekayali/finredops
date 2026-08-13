"""Authenticated tenant routing and authorization above institution-scoped persistence.

This layer consumes an already verified OIDC identity artifact and an explicit,
digest-bound institution routing policy. It never accepts an institution id from
an untrusted request as sufficient authority. Authorization is exact-subject,
exact-provider-configuration, exact-institution and capability bound.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crypto_provider import KmsHsmProvider
from .institution import InstitutionSecurityContext
from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .oidc_identity import OIDCIdentityVerification, oidc_verification_from_document
from .store import SQLiteGovernanceStore

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_AUTH_ID = re.compile(r"^FRX-TNA-[A-F0-9]{24}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FINREDOPS_ROLES = frozenset(
    {"qualified_tester", "review_governor", "business_risk_owner", "report_approver"}
)
_CAPABILITIES = frozenset({"store_read", "store_write", "audit_verify", "crypto_use"})
_GRANT_STATUSES = frozenset({"active", "disabled"})


class TenantAuthorizationError(ValueError):
    """Raised when tenant routing or capability authorization fails closed."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise TenantAuthorizationError(f"{name} is not a valid bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise TenantAuthorizationError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise TenantAuthorizationError(f"{name} must be a bounded non-empty string.")
    return value.strip()


def _unique_values(
    values: Sequence[str], *, allowed: frozenset[str], name: str, maximum: int = 32
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)) or not 1 <= len(values) <= maximum:
        raise TenantAuthorizationError(f"{name} must contain 1 to {maximum} values.")
    normalized = tuple(sorted(set(values)))
    if len(normalized) != len(values) or any(item not in allowed for item in normalized):
        raise TenantAuthorizationError(f"{name} contains duplicate or unsupported values.")
    return normalized


def _derived_id(body: Mapping[str, Any]) -> str:
    return f"FRX-TNA-{sha256_digest(body)[:24].upper()}"


def _routing_policy_id(
    context: InstitutionSecurityContext, verification: OIDCIdentityVerification
) -> str:
    seed = {
        "institution_id": context.institution_id,
        "oidc_provider_id": verification.provider_id,
        "oidc_provider_config_digest": verification.provider_config_digest,
    }
    return f"FRX-TRP-{sha256_digest(seed)[:24].upper()}"


@dataclass(frozen=True, slots=True)
class TenantSubjectGrant:
    subject: str
    roles: tuple[str, ...]
    capabilities: tuple[str, ...]
    status: str = "active"

    def __post_init__(self) -> None:
        _identifier(self.subject, "subject")
        object.__setattr__(
            self,
            "roles",
            _unique_values(self.roles, allowed=_FINREDOPS_ROLES, name="roles", maximum=8),
        )
        object.__setattr__(
            self,
            "capabilities",
            _unique_values(
                self.capabilities, allowed=_CAPABILITIES, name="capabilities", maximum=8
            ),
        )
        if self.status not in _GRANT_STATUSES:
            raise TenantAuthorizationError("Unsupported tenant grant status.")

    def as_dict(self) -> dict[str, Any]:
        return to_primitive(self)


@dataclass(frozen=True, slots=True)
class TenantRoutingPolicy:
    policy_id: str
    institution_id: str
    oidc_provider_id: str
    oidc_provider_config_digest: str
    grants: tuple[TenantSubjectGrant, ...]
    schema_version: str = "finredops.tenant-routing-policy.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "finredops.tenant-routing-policy.v1":
            raise TenantAuthorizationError("Unsupported tenant routing policy schema.")
        _identifier(self.policy_id, "policy_id")
        _identifier(self.institution_id, "institution_id")
        _identifier(self.oidc_provider_id, "oidc_provider_id")
        _digest(self.oidc_provider_config_digest, "oidc_provider_config_digest")
        if not 1 <= len(self.grants) <= 512:
            raise TenantAuthorizationError("Tenant routing policy requires 1 to 512 grants.")
        subjects = [item.subject for item in self.grants]
        if len(set(subjects)) != len(subjects):
            raise TenantAuthorizationError("Tenant routing policy subjects must be unique.")
        object.__setattr__(self, "grants", tuple(sorted(self.grants, key=lambda item: item.subject)))

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "institution_id": self.institution_id,
            "oidc_provider_id": self.oidc_provider_id,
            "oidc_provider_config_digest": self.oidc_provider_config_digest,
            "grants": [item.as_dict() for item in self.grants],
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**self.core(), "policy_digest": self.digest()}

    def grant_for_subject(self, subject: str) -> TenantSubjectGrant:
        _identifier(subject, "subject")
        matches = [item for item in self.grants if item.subject == subject]
        if len(matches) != 1:
            raise TenantAuthorizationError("OIDC subject has no exact tenant routing grant.")
        grant = matches[0]
        if grant.status != "active":
            raise TenantAuthorizationError("Tenant routing grant is disabled.")
        return grant


def tenant_policy_from_document(document: Any) -> TenantRoutingPolicy:
    required = {
        "schema_version",
        "policy_id",
        "institution_id",
        "oidc_provider_id",
        "oidc_provider_config_digest",
        "grants",
        "policy_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise TenantAuthorizationError("Tenant routing policy does not match the v1 contract.")
    if not isinstance(document["grants"], list):
        raise TenantAuthorizationError("Tenant routing grants must be an array.")
    grants: list[TenantSubjectGrant] = []
    grant_fields = {"subject", "roles", "capabilities", "status"}
    for index, item in enumerate(document["grants"]):
        if not isinstance(item, Mapping) or set(item) != grant_fields:
            raise TenantAuthorizationError(f"grants[{index}] does not match the v1 contract.")
        if not isinstance(item["roles"], list) or not isinstance(item["capabilities"], list):
            raise TenantAuthorizationError(f"grants[{index}] roles/capabilities must be arrays.")
        grants.append(
            TenantSubjectGrant(
                subject=str(item["subject"]),
                roles=tuple(str(value) for value in item["roles"]),
                capabilities=tuple(str(value) for value in item["capabilities"]),
                status=str(item["status"]),
            )
        )
    policy = TenantRoutingPolicy(
        policy_id=str(document["policy_id"]),
        institution_id=str(document["institution_id"]),
        oidc_provider_id=str(document["oidc_provider_id"]),
        oidc_provider_config_digest=str(document["oidc_provider_config_digest"]),
        grants=tuple(grants),
        schema_version=str(document["schema_version"]),
    )
    if document["policy_digest"] != policy.digest():
        raise TenantAuthorizationError("Tenant routing policy digest is invalid.")
    return policy


def tenant_policy_template(
    *, context: InstitutionSecurityContext, verification: OIDCIdentityVerification
) -> dict[str, Any]:
    policy = TenantRoutingPolicy(
        policy_id=_routing_policy_id(context, verification),
        institution_id=context.institution_id,
        oidc_provider_id=verification.provider_id,
        oidc_provider_config_digest=verification.provider_config_digest,
        grants=(
            TenantSubjectGrant(
                subject=verification.subject,
                roles=verification.roles,
                capabilities=("store_read", "audit_verify"),
            ),
        ),
    )
    return policy.as_dict()


@dataclass(frozen=True, slots=True)
class TenantAuthorization:
    authorization_id: str
    institution_id: str
    institution_context_digest: str
    policy_id: str
    policy_digest: str
    verification_id: str
    verification_digest: str
    provider_id: str
    subject: str
    roles: tuple[str, ...]
    capabilities: tuple[str, ...]
    authorized_at: datetime
    expires_at: int

    def __post_init__(self) -> None:
        if not _AUTH_ID.fullmatch(self.authorization_id):
            raise TenantAuthorizationError("Invalid tenant authorization id.")
        for name in ("institution_id", "policy_id", "verification_id", "provider_id", "subject"):
            _identifier(getattr(self, name), name)
        for name in ("institution_context_digest", "policy_digest", "verification_digest"):
            _digest(getattr(self, name), name)
        object.__setattr__(
            self,
            "roles",
            _unique_values(self.roles, allowed=_FINREDOPS_ROLES, name="roles", maximum=8),
        )
        object.__setattr__(
            self,
            "capabilities",
            _unique_values(
                self.capabilities, allowed=_CAPABILITIES, name="capabilities", maximum=8
            ),
        )
        object.__setattr__(self, "authorized_at", ensure_aware(self.authorized_at))
        if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, int):
            raise TenantAuthorizationError("expires_at must be an integer NumericDate.")
        if self.expires_at <= int(self.authorized_at.timestamp()):
            raise TenantAuthorizationError("Tenant authorization must expire after authorization time.")
        if self.authorization_id != _derived_id(self.body()):
            raise TenantAuthorizationError("Tenant authorization id does not match its payload.")

    def body(self) -> dict[str, Any]:
        return {
            "institution_id": self.institution_id,
            "institution_context_digest": self.institution_context_digest,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "verification_id": self.verification_id,
            "verification_digest": self.verification_digest,
            "provider_id": self.provider_id,
            "subject": self.subject,
            "roles": self.roles,
            "capabilities": self.capabilities,
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
        }

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.tenant-authorization.v1",
            "authorization_id": self.authorization_id,
            **to_primitive(self.body()),
            "external_idp_protocol_verified": True,
            "tenant_route_authorized": True,
        }
        return {**body, "authorization_digest": sha256_digest(body)}


def tenant_authorization_from_document(document: Any) -> TenantAuthorization:
    fields = {
        "schema_version",
        "authorization_id",
        "institution_id",
        "institution_context_digest",
        "policy_id",
        "policy_digest",
        "verification_id",
        "verification_digest",
        "provider_id",
        "subject",
        "roles",
        "capabilities",
        "authorized_at",
        "expires_at",
        "external_idp_protocol_verified",
        "tenant_route_authorized",
        "authorization_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise TenantAuthorizationError("Tenant authorization does not match the v1 contract.")
    if (
        document["schema_version"] != "finredops.tenant-authorization.v1"
        or document["external_idp_protocol_verified"] is not True
        or document["tenant_route_authorized"] is not True
    ):
        raise TenantAuthorizationError("Tenant authorization safety markers are invalid.")
    if not isinstance(document["roles"], list) or not isinstance(document["capabilities"], list):
        raise TenantAuthorizationError("Tenant authorization roles/capabilities must be arrays.")
    authorization = TenantAuthorization(
        authorization_id=str(document["authorization_id"]),
        institution_id=str(document["institution_id"]),
        institution_context_digest=str(document["institution_context_digest"]),
        policy_id=str(document["policy_id"]),
        policy_digest=str(document["policy_digest"]),
        verification_id=str(document["verification_id"]),
        verification_digest=str(document["verification_digest"]),
        provider_id=str(document["provider_id"]),
        subject=str(document["subject"]),
        roles=tuple(str(item) for item in document["roles"]),
        capabilities=tuple(str(item) for item in document["capabilities"]),
        authorized_at=parse_datetime(str(document["authorized_at"])),
        expires_at=document["expires_at"],
    )
    if document["authorization_digest"] != authorization.as_dict()["authorization_digest"]:
        raise TenantAuthorizationError("Tenant authorization digest is invalid.")
    return authorization


def _effective_grant(
    verification: OIDCIdentityVerification,
    policy: TenantRoutingPolicy,
    context: InstitutionSecurityContext,
) -> tuple[TenantSubjectGrant, tuple[str, ...]]:
    if verification.provider_id != policy.oidc_provider_id:
        raise TenantAuthorizationError("OIDC provider is not authorized by the tenant routing policy.")
    if verification.provider_config_digest != policy.oidc_provider_config_digest:
        raise TenantAuthorizationError(
            "OIDC provider configuration does not match the tenant routing policy."
        )
    if policy.institution_id != context.institution_id:
        raise TenantAuthorizationError("Tenant routing policy and institution context do not match.")
    grant = policy.grant_for_subject(verification.subject)
    roles = tuple(sorted(set(verification.roles) & set(grant.roles)))
    if not roles:
        raise TenantAuthorizationError("OIDC roles do not intersect the subject's tenant grant.")
    return grant, roles


def authorize_tenant_route(
    verification: OIDCIdentityVerification,
    policy: TenantRoutingPolicy,
    context: InstitutionSecurityContext,
    *,
    requested_capabilities: Sequence[str],
    as_of: datetime,
) -> TenantAuthorization:
    effective = ensure_aware(as_of)
    now = int(effective.timestamp())
    if effective < verification.verified_at:
        raise TenantAuthorizationError("Tenant authorization cannot predate OIDC verification.")
    if now < verification.issued_at or now >= verification.expires_at:
        raise TenantAuthorizationError("OIDC verification is not currently valid for tenant routing.")
    grant, roles = _effective_grant(verification, policy, context)
    capabilities = _unique_values(
        tuple(requested_capabilities),
        allowed=_CAPABILITIES,
        name="requested_capabilities",
        maximum=8,
    )
    if not set(capabilities).issubset(grant.capabilities):
        raise TenantAuthorizationError("Requested tenant capability exceeds the subject grant.")
    verification_digest = verification.as_dict()["verification_digest"]
    body = {
        "institution_id": context.institution_id,
        "institution_context_digest": context.digest(),
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest(),
        "verification_id": verification.verification_id,
        "verification_digest": verification_digest,
        "provider_id": verification.provider_id,
        "subject": verification.subject,
        "roles": roles,
        "capabilities": capabilities,
        "authorized_at": effective,
        "expires_at": verification.expires_at,
    }
    return TenantAuthorization(authorization_id=_derived_id(body), **body)


def verify_tenant_authorization(
    authorization: TenantAuthorization,
    verification: OIDCIdentityVerification,
    policy: TenantRoutingPolicy,
    context: InstitutionSecurityContext,
    *,
    as_of: datetime,
) -> None:
    effective = ensure_aware(as_of)
    now = int(effective.timestamp())
    if now >= authorization.expires_at or now >= verification.expires_at:
        raise TenantAuthorizationError("Tenant authorization or source OIDC verification has expired.")
    if effective < authorization.authorized_at or effective < verification.verified_at:
        raise TenantAuthorizationError("Tenant authorization verification time is invalid.")
    grant, roles = _effective_grant(verification, policy, context)
    expected = {
        "institution_id": context.institution_id,
        "institution_context_digest": context.digest(),
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest(),
        "verification_id": verification.verification_id,
        "verification_digest": verification.as_dict()["verification_digest"],
        "provider_id": verification.provider_id,
        "subject": verification.subject,
        "roles": roles,
        "expires_at": verification.expires_at,
    }
    actual = authorization.body()
    for name, value in expected.items():
        if actual[name] != value:
            raise TenantAuthorizationError(f"Tenant authorization {name} binding is stale or invalid.")
    if not set(authorization.capabilities).issubset(grant.capabilities):
        raise TenantAuthorizationError("Tenant authorization capabilities exceed the current grant.")


@dataclass(frozen=True, slots=True)
class AuthorizedTenantSession:
    authorization: TenantAuthorization
    verification: OIDCIdentityVerification
    policy: TenantRoutingPolicy
    context: InstitutionSecurityContext
    validated_at: datetime

    @classmethod
    def create(
        cls,
        authorization: TenantAuthorization,
        verification: OIDCIdentityVerification,
        policy: TenantRoutingPolicy,
        context: InstitutionSecurityContext,
        *,
        as_of: datetime,
    ) -> "AuthorizedTenantSession":
        verify_tenant_authorization(
            authorization, verification, policy, context, as_of=as_of
        )
        return cls(authorization, verification, policy, context, ensure_aware(as_of))

    def require(self, capability: str) -> None:
        if capability not in _CAPABILITIES:
            raise TenantAuthorizationError("Unknown tenant capability.")
        if capability not in self.authorization.capabilities:
            raise TenantAuthorizationError(
                f"Tenant authorization does not grant required capability {capability!r}."
            )

    def open_store(
        self,
        path: str | Path,
        *,
        access: str = "read",
        crypto_provider: KmsHsmProvider | None = None,
    ) -> SQLiteGovernanceStore:
        if access not in {"read", "write"}:
            raise TenantAuthorizationError("Store access must be 'read' or 'write'.")
        capability = "store_read" if access == "read" else "store_write"
        self.require(capability)
        if access == "write" and crypto_provider is None:
            raise TenantAuthorizationError(
                "Authorized tenant writes require the institution crypto provider to avoid plaintext persistence."
            )
        if crypto_provider is not None:
            return SQLiteGovernanceStore(
                path,
                institution_id=self.context.institution_id,
                security_context=self.context,
                crypto_provider=crypto_provider,
            )
        return SQLiteGovernanceStore(path, institution_id=self.context.institution_id)


def load_oidc_verification(document: Any) -> OIDCIdentityVerification:
    """Narrow public helper used by tenant-routing CLI/tests."""

    return oidc_verification_from_document(document)
