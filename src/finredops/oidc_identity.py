"""Offline OIDC ID-token verification and binding to FinRedOps signed identities.

FinRedOps never fetches discovery metadata or JWKS in this module. Operators
provide a pinned provider configuration, a bounded JWKS document, and an ID
token obtained from an external OpenID Provider. The token is verified against
configured algorithms and keys, then its subject/role claims can be bound to an
already signed FinRedOps reviewer or approval object.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

import jwt

from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .review import read_review_json
from .signed_approvals import approval_signature_from_document
from .trust import identity_assertion_from_document

_MAX_TOKEN_BYTES = 64_000
_MAX_JWKS_KEYS = 128
_ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
_FINREDOPS_ROLES = frozenset(
    {"qualified_tester", "review_governor", "business_risk_owner", "report_approver"}
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_VERIFICATION_ID = re.compile(r"^FRX-OIDC-[A-F0-9]{24}$")
_BINDING_ID = re.compile(r"^FRX-OIDB-[A-F0-9]{24}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class OIDCIdentityError(ValueError):
    """Raised when external IdP verification or identity binding fails closed."""


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or _CONTROL.search(value):
        raise OIDCIdentityError(f"{name} must be a bounded non-empty string.")
    return value.strip()


def _identifier(value: Any, name: str) -> str:
    value = _text(value, name, 200)
    if not _ID.fullmatch(value):
        raise OIDCIdentityError(f"{name} is not a valid bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise OIDCIdentityError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _https_issuer(value: Any) -> str:
    issuer = _text(value, "issuer", 512)
    parsed = urlparse(issuer)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment or parsed.query:
        raise OIDCIdentityError("OIDC issuer must be an exact HTTPS origin/path without query or fragment.")
    return issuer.rstrip("/")


def _int(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise OIDCIdentityError(f"{name} must be an integer between {minimum} and {maximum}.")
    return value


def _numeric_date(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise OIDCIdentityError(f"OIDC claim {name!r} must be an integer NumericDate.")
    return value


def _derived_id(prefix: str, body: Mapping[str, Any]) -> str:
    return f"{prefix}-{sha256_digest(body)[:24].upper()}"


@dataclass(frozen=True, slots=True)
class OIDCProviderConfig:
    provider_id: str
    issuer: str
    client_id: str
    allowed_algorithms: tuple[str, ...]
    role_claim: str
    required_acr: tuple[str, ...]
    max_auth_age_seconds: int
    max_token_lifetime_seconds: int
    clock_skew_seconds: int

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "provider_id")
        object.__setattr__(self, "issuer", _https_issuer(self.issuer))
        _text(self.client_id, "client_id", 512)
        algorithms = tuple(sorted(set(self.allowed_algorithms)))
        if not algorithms or any(item not in _ALLOWED_ALGORITHMS for item in algorithms):
            raise OIDCIdentityError("allowed_algorithms must contain only supported asymmetric algorithms.")
        object.__setattr__(self, "allowed_algorithms", algorithms)
        _text(self.role_claim, "role_claim", 256)
        acr = tuple(sorted(set(self.required_acr)))
        if len(acr) > 16:
            raise OIDCIdentityError("required_acr is limited to 16 values.")
        for index, item in enumerate(acr):
            _text(item, f"required_acr[{index}]", 256)
        object.__setattr__(self, "required_acr", acr)
        _int(self.max_auth_age_seconds, "max_auth_age_seconds", minimum=60, maximum=86_400)
        _int(self.max_token_lifetime_seconds, "max_token_lifetime_seconds", minimum=60, maximum=86_400)
        _int(self.clock_skew_seconds, "clock_skew_seconds", minimum=0, maximum=300)

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.oidc-provider.v1",
            "provider_id": self.provider_id,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "allowed_algorithms": list(self.allowed_algorithms),
            "role_claim": self.role_claim,
            "required_acr": list(self.required_acr),
            "max_auth_age_seconds": self.max_auth_age_seconds,
            "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            "clock_skew_seconds": self.clock_skew_seconds,
        }
        return {**body, "provider_config_digest": sha256_digest(body)}

    def digest(self) -> str:
        return self.as_dict()["provider_config_digest"]


def provider_config_from_document(document: Any) -> OIDCProviderConfig:
    required = {
        "schema_version",
        "provider_id",
        "issuer",
        "client_id",
        "allowed_algorithms",
        "role_claim",
        "required_acr",
        "max_auth_age_seconds",
        "max_token_lifetime_seconds",
        "clock_skew_seconds",
    }
    metadata = {"provider_config_digest"}
    if not isinstance(document, Mapping) or set(document) - metadata != required:
        raise OIDCIdentityError("OIDC provider document does not match the v1 contract.")
    if document["schema_version"] != "finredops.oidc-provider.v1":
        raise OIDCIdentityError("Unsupported OIDC provider schema.")
    if not isinstance(document["allowed_algorithms"], list) or not isinstance(document["required_acr"], list):
        raise OIDCIdentityError("OIDC provider algorithms and ACR values must be arrays.")
    config = OIDCProviderConfig(
        provider_id=str(document["provider_id"]),
        issuer=str(document["issuer"]),
        client_id=str(document["client_id"]),
        allowed_algorithms=tuple(str(item) for item in document["allowed_algorithms"]),
        role_claim=str(document["role_claim"]),
        required_acr=tuple(str(item) for item in document["required_acr"]),
        max_auth_age_seconds=document["max_auth_age_seconds"],
        max_token_lifetime_seconds=document["max_token_lifetime_seconds"],
        clock_skew_seconds=document["clock_skew_seconds"],
    )
    supplied = document.get("provider_config_digest")
    if supplied is not None and supplied != config.digest():
        raise OIDCIdentityError("OIDC provider configuration digest is invalid.")
    return config


def provider_template_document() -> dict[str, Any]:
    return {
        "schema_version": "finredops.oidc-provider.v1",
        "provider_id": "TODO",
        "issuer": "https://idp.example.test",
        "client_id": "TODO",
        "allowed_algorithms": ["RS256"],
        "role_claim": "roles",
        "required_acr": ["TODO"],
        "max_auth_age_seconds": 3600,
        "max_token_lifetime_seconds": 3600,
        "clock_skew_seconds": 60,
    }


def _read_token(path: Path) -> str:
    if not path.is_file():
        raise OIDCIdentityError("ID token input must be a regular file.")
    size = path.stat().st_size
    if not 1 <= size <= _MAX_TOKEN_BYTES:
        raise OIDCIdentityError("ID token input exceeds the bounded token size.")
    token = path.read_text(encoding="utf-8").strip()
    if len(token.encode("utf-8")) > _MAX_TOKEN_BYTES or token.count(".") != 2:
        raise OIDCIdentityError("ID token must be one bounded compact JWT.")
    return token


def _select_jwk(jwks: Any, *, kid: str, algorithm: str) -> tuple[dict[str, Any], str]:
    if not isinstance(jwks, Mapping) or set(jwks) != {"keys"} or not isinstance(jwks["keys"], list):
        raise OIDCIdentityError("JWKS document must contain only a keys array.")
    keys = jwks["keys"]
    if not 1 <= len(keys) <= _MAX_JWKS_KEYS:
        raise OIDCIdentityError("JWKS key count is outside the allowed range.")
    matches = [item for item in keys if isinstance(item, Mapping) and item.get("kid") == kid]
    if len(matches) != 1:
        raise OIDCIdentityError("JWKS must contain exactly one signing key for the token kid.")
    key = dict(matches[0])
    if key.get("kty") == "oct":
        raise OIDCIdentityError("Symmetric JWKS keys are not accepted for OIDC identity verification.")
    if key.get("use") not in (None, "sig"):
        raise OIDCIdentityError("Selected JWK is not marked for signature use.")
    key_ops = key.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise OIDCIdentityError("Selected JWK does not permit signature verification.")
    if key.get("alg") not in (None, algorithm):
        raise OIDCIdentityError("Selected JWK algorithm does not match the configured token algorithm.")
    return key, sha256_digest(jwks)


def _roles(claim: Any) -> tuple[str, ...]:
    if isinstance(claim, str):
        values = (claim,)
    elif isinstance(claim, list) and all(isinstance(item, str) for item in claim):
        values = tuple(claim)
    else:
        raise OIDCIdentityError("OIDC role claim must be a string or string array.")
    roles = tuple(sorted(set(values) & _FINREDOPS_ROLES))
    if not roles:
        raise OIDCIdentityError("OIDC role claim does not authorize a FinRedOps role.")
    return roles


@dataclass(frozen=True, slots=True)
class OIDCIdentityVerification:
    verification_id: str
    provider_id: str
    provider_config_digest: str
    jwks_digest: str
    issuer: str
    client_id: str
    subject: str
    roles: tuple[str, ...]
    acr: str
    token_kid: str
    token_algorithm: str
    token_digest: str
    nonce_digest: str
    issued_at: int
    expires_at: int
    auth_time: int
    verified_at: datetime

    def __post_init__(self) -> None:
        if not _VERIFICATION_ID.fullmatch(self.verification_id):
            raise OIDCIdentityError("Invalid OIDC verification id.")
        _identifier(self.provider_id, "provider_id")
        for name in ("provider_config_digest", "jwks_digest", "token_digest", "nonce_digest"):
            _digest(getattr(self, name), name)
        object.__setattr__(self, "issuer", _https_issuer(self.issuer))
        _text(self.client_id, "client_id", 512)
        _identifier(self.subject, "subject")
        roles = tuple(sorted(set(self.roles)))
        if not roles or any(item not in _FINREDOPS_ROLES for item in roles):
            raise OIDCIdentityError("OIDC verification roles are invalid.")
        object.__setattr__(self, "roles", roles)
        _text(self.acr, "acr", 256)
        _text(self.token_kid, "token_kid", 256)
        if self.token_algorithm not in _ALLOWED_ALGORITHMS:
            raise OIDCIdentityError("OIDC verification algorithm is invalid.")
        for name in ("issued_at", "expires_at", "auth_time"):
            if isinstance(getattr(self, name), bool) or not isinstance(getattr(self, name), int):
                raise OIDCIdentityError(f"{name} must be an integer NumericDate.")
        object.__setattr__(self, "verified_at", ensure_aware(self.verified_at))
        if self.verification_id != _derived_id("FRX-OIDC", self.body()):
            raise OIDCIdentityError("OIDC verification id does not match its payload.")

    def body(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_config_digest": self.provider_config_digest,
            "jwks_digest": self.jwks_digest,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "subject": self.subject,
            "roles": self.roles,
            "acr": self.acr,
            "token_kid": self.token_kid,
            "token_algorithm": self.token_algorithm,
            "token_digest": self.token_digest,
            "nonce_digest": self.nonce_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "auth_time": self.auth_time,
            "verified_at": self.verified_at,
        }

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.oidc-identity-verification.v1",
            "verification_id": self.verification_id,
            **to_primitive(self.body()),
            "external_idp_protocol_verified": True,
            "raw_id_token_retained": False,
        }
        return {**body, "verification_digest": sha256_digest(body)}


def oidc_verification_from_document(document: Any) -> OIDCIdentityVerification:
    fields = {
        "schema_version", "verification_id", "provider_id", "provider_config_digest", "jwks_digest",
        "issuer", "client_id", "subject", "roles", "acr", "token_kid", "token_algorithm",
        "token_digest", "nonce_digest", "issued_at", "expires_at", "auth_time", "verified_at",
        "external_idp_protocol_verified", "raw_id_token_retained", "verification_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise OIDCIdentityError("OIDC verification document does not match the v1 contract.")
    if document["schema_version"] != "finredops.oidc-identity-verification.v1":
        raise OIDCIdentityError("Unsupported OIDC verification schema.")
    if document["external_idp_protocol_verified"] is not True or document["raw_id_token_retained"] is not False:
        raise OIDCIdentityError("OIDC verification safety markers are invalid.")
    if not isinstance(document["roles"], list):
        raise OIDCIdentityError("OIDC verification roles must be an array.")
    result = OIDCIdentityVerification(
        verification_id=str(document["verification_id"]), provider_id=str(document["provider_id"]),
        provider_config_digest=str(document["provider_config_digest"]), jwks_digest=str(document["jwks_digest"]),
        issuer=str(document["issuer"]), client_id=str(document["client_id"]), subject=str(document["subject"]),
        roles=tuple(str(item) for item in document["roles"]), acr=str(document["acr"]),
        token_kid=str(document["token_kid"]), token_algorithm=str(document["token_algorithm"]),
        token_digest=str(document["token_digest"]), nonce_digest=str(document["nonce_digest"]),
        issued_at=document["issued_at"], expires_at=document["expires_at"], auth_time=document["auth_time"],
        verified_at=parse_datetime(str(document["verified_at"])),
    )
    if document["verification_digest"] != result.as_dict()["verification_digest"]:
        raise OIDCIdentityError("OIDC verification digest is invalid.")
    return result


def verify_oidc_id_token(
    token: str,
    config: OIDCProviderConfig,
    jwks: Any,
    *,
    expected_nonce: str,
    as_of: datetime,
) -> OIDCIdentityVerification:
    expected_nonce = _text(expected_nonce, "expected_nonce", 512)
    effective = ensure_aware(as_of)
    if len(token.encode("utf-8")) > _MAX_TOKEN_BYTES or token.count(".") != 2:
        raise OIDCIdentityError("ID token must be one bounded compact JWT.")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OIDCIdentityError(f"Could not parse ID token header: {exc}") from exc
    algorithm = header.get("alg")
    kid = header.get("kid")
    if not isinstance(algorithm, str) or algorithm not in config.allowed_algorithms:
        raise OIDCIdentityError("ID token algorithm is not in the pinned provider allow-list.")
    if not isinstance(kid, str) or not kid.strip():
        raise OIDCIdentityError("ID token requires a non-empty kid header.")
    key_document, jwks_digest = _select_jwk(jwks, kid=kid, algorithm=algorithm)
    try:
        key = jwt.PyJWK.from_dict(key_document, algorithm=algorithm)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=list(config.allowed_algorithms),
            issuer=config.issuer,
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "require": ["iss", "sub", "aud", "exp", "iat", "auth_time", "acr", "nonce"],
            },
        )
    except jwt.PyJWTError as exc:
        raise OIDCIdentityError(f"OIDC ID token signature/issuer validation failed: {exc}") from exc

    subject = _identifier(claims.get("sub"), "sub")
    audience = claims.get("aud")
    if isinstance(audience, str):
        audiences = (audience,)
    elif isinstance(audience, list) and audience and all(isinstance(item, str) for item in audience):
        audiences = tuple(audience)
    else:
        raise OIDCIdentityError("OIDC aud claim must be a string or non-empty string array.")
    if set(audiences) != {config.client_id}:
        raise OIDCIdentityError("OIDC aud claim must exactly match the configured client_id.")
    if len(audiences) > 1 and claims.get("azp") != config.client_id:
        raise OIDCIdentityError("Multi-audience ID token requires azp equal to the configured client_id.")
    if "azp" in claims and claims.get("azp") != config.client_id:
        raise OIDCIdentityError("OIDC azp claim does not match the configured client_id.")
    if claims.get("nonce") != expected_nonce:
        raise OIDCIdentityError("OIDC nonce does not match the expected authentication transaction.")

    issued_at = _numeric_date(claims, "iat")
    expires_at = _numeric_date(claims, "exp")
    auth_time = _numeric_date(claims, "auth_time")
    now = int(effective.timestamp())
    skew = config.clock_skew_seconds
    if issued_at > now + skew:
        raise OIDCIdentityError("OIDC token was issued in the future beyond configured clock skew.")
    if expires_at <= now - skew:
        raise OIDCIdentityError("OIDC token is expired.")
    if expires_at <= issued_at or expires_at - issued_at > config.max_token_lifetime_seconds:
        raise OIDCIdentityError("OIDC token lifetime exceeds the configured maximum.")
    nbf = claims.get("nbf")
    if nbf is not None:
        if isinstance(nbf, bool) or not isinstance(nbf, int) or nbf > now + skew:
            raise OIDCIdentityError("OIDC token is not yet valid.")
    if auth_time > now + skew or now - auth_time > config.max_auth_age_seconds + skew:
        raise OIDCIdentityError("OIDC authentication age exceeds the configured maximum.")

    acr = _text(claims.get("acr"), "acr", 256)
    if config.required_acr and acr not in config.required_acr:
        raise OIDCIdentityError("OIDC acr claim does not satisfy the configured assurance requirement.")
    roles = _roles(claims.get(config.role_claim))
    token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    nonce_digest = hashlib.sha256(expected_nonce.encode("utf-8")).hexdigest()
    core = {
        "provider_id": config.provider_id,
        "provider_config_digest": config.digest(),
        "jwks_digest": jwks_digest,
        "issuer": config.issuer,
        "client_id": config.client_id,
        "subject": subject,
        "roles": roles,
        "acr": acr,
        "token_kid": kid,
        "token_algorithm": algorithm,
        "token_digest": token_digest,
        "nonce_digest": nonce_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "auth_time": auth_time,
        "verified_at": effective,
    }
    return OIDCIdentityVerification(
        verification_id=_derived_id("FRX-OIDC", core),
        **core,
    )


def verify_oidc_id_token_from_files(
    *,
    provider_config_path: Path,
    jwks_path: Path,
    id_token_path: Path,
    expected_nonce: str,
    as_of: datetime,
) -> OIDCIdentityVerification:
    config = provider_config_from_document(read_review_json(provider_config_path))
    jwks = read_review_json(jwks_path)
    token = _read_token(id_token_path)
    return verify_oidc_id_token(token, config, jwks, expected_nonce=expected_nonce, as_of=as_of)


@dataclass(frozen=True, slots=True)
class OIDCIdentityBinding:
    binding_id: str
    verification_id: str
    verification_digest: str
    protected_schema: str
    protected_id: str
    protected_digest: str
    subject: str
    role: str
    engagement_id: str
    bound_at: datetime

    def body(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "verification_digest": self.verification_digest,
            "protected_schema": self.protected_schema,
            "protected_id": self.protected_id,
            "protected_digest": self.protected_digest,
            "subject": self.subject,
            "role": self.role,
            "engagement_id": self.engagement_id,
            "bound_at": self.bound_at,
        }

    def __post_init__(self) -> None:
        if not _BINDING_ID.fullmatch(self.binding_id):
            raise OIDCIdentityError("Invalid OIDC binding id.")
        if not _VERIFICATION_ID.fullmatch(self.verification_id):
            raise OIDCIdentityError("Invalid OIDC verification reference.")
        for name in ("verification_digest", "protected_digest"):
            _digest(getattr(self, name), name)
        if self.protected_schema not in {"finredops.identity-assertion.v1", "finredops.approval-signature.v1"}:
            raise OIDCIdentityError("OIDC binding protects an unsupported signed-object schema.")
        _identifier(self.protected_id, "protected_id")
        _identifier(self.subject, "subject")
        if self.role not in _FINREDOPS_ROLES:
            raise OIDCIdentityError("OIDC binding role is invalid.")
        _identifier(self.engagement_id, "engagement_id")
        object.__setattr__(self, "bound_at", ensure_aware(self.bound_at))
        if self.binding_id != _derived_id("FRX-OIDB", self.body()):
            raise OIDCIdentityError("OIDC binding id does not match its payload.")

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.oidc-identity-binding.v1",
            "binding_id": self.binding_id,
            **to_primitive(self.body()),
            "external_idp_protocol_verified": True,
        }
        return {**body, "binding_digest": sha256_digest(body)}


def oidc_binding_from_document(document: Any) -> OIDCIdentityBinding:
    fields = {
        "schema_version", "binding_id", "verification_id", "verification_digest", "protected_schema",
        "protected_id", "protected_digest", "subject", "role", "engagement_id", "bound_at",
        "external_idp_protocol_verified", "binding_digest",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise OIDCIdentityError("OIDC binding document does not match the v1 contract.")
    if document["schema_version"] != "finredops.oidc-identity-binding.v1" or document["external_idp_protocol_verified"] is not True:
        raise OIDCIdentityError("Unsupported or invalid OIDC binding document.")
    binding = OIDCIdentityBinding(
        binding_id=str(document["binding_id"]), verification_id=str(document["verification_id"]),
        verification_digest=str(document["verification_digest"]), protected_schema=str(document["protected_schema"]),
        protected_id=str(document["protected_id"]), protected_digest=str(document["protected_digest"]),
        subject=str(document["subject"]), role=str(document["role"]), engagement_id=str(document["engagement_id"]),
        bound_at=parse_datetime(str(document["bound_at"])),
    )
    if document["binding_digest"] != binding.as_dict()["binding_digest"]:
        raise OIDCIdentityError("OIDC binding digest is invalid.")
    return binding


def bind_oidc_identity(
    verification: OIDCIdentityVerification,
    protected_document: Any,
    *,
    as_of: datetime,
) -> OIDCIdentityBinding:
    effective = ensure_aware(as_of)
    verification_doc = verification.as_dict()
    if int(effective.timestamp()) > verification.expires_at:
        raise OIDCIdentityError("OIDC verification token has expired before identity binding.")
    if not isinstance(protected_document, Mapping):
        raise OIDCIdentityError("Protected signed identity must be a JSON object.")
    schema = protected_document.get("schema_version")
    if schema == "finredops.identity-assertion.v1":
        protected = identity_assertion_from_document(protected_document)
        protected_id, subject, role, engagement_id = (
            protected.assertion_id, protected.subject, protected.role, protected.engagement_id
        )
    elif schema == "finredops.approval-signature.v1":
        protected = approval_signature_from_document(protected_document)
        protected_id, subject, role, engagement_id = (
            protected.signature_id, protected.subject, protected.role, protected.engagement_id
        )
    else:
        raise OIDCIdentityError("Protected document is not a supported signed identity object.")
    if subject != verification.subject:
        raise OIDCIdentityError("OIDC subject does not match the signed FinRedOps subject.")
    if role not in verification.roles:
        raise OIDCIdentityError("OIDC role claims do not authorize the signed FinRedOps role.")
    body = {
        "verification_id": verification.verification_id,
        "verification_digest": verification_doc["verification_digest"],
        "protected_schema": schema,
        "protected_id": protected_id,
        "protected_digest": sha256_digest(protected_document),
        "subject": subject,
        "role": role,
        "engagement_id": engagement_id,
        "bound_at": effective,
    }
    return OIDCIdentityBinding(binding_id=_derived_id("FRX-OIDB", body), **body)


@dataclass(frozen=True, slots=True)
class OIDCWorkflowResolution:
    engagement_id: str
    binding_ids: tuple[str, ...]
    protected_ids: tuple[str, ...]
    verification_ids: tuple[str, ...]
    subjects: tuple[str, ...]
    roles: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.oidc-workflow-resolution.v1",
            "engagement_id": self.engagement_id,
            "binding_ids": list(self.binding_ids),
            "protected_ids": list(self.protected_ids),
            "verification_ids": list(self.verification_ids),
            "subjects": list(self.subjects),
            "roles": list(self.roles),
            "external_idp_protocol_verified": True,
            "exact_binding_coverage": True,
        }
        return {**body, "resolution_digest": sha256_digest(body)}


def resolve_oidc_workflow_bindings(
    bindings: Sequence[OIDCIdentityBinding],
    protected_documents: Sequence[Any],
    *,
    engagement_id: str,
) -> OIDCWorkflowResolution:
    engagement_id = _identifier(engagement_id, "engagement_id")
    if not bindings or not protected_documents:
        raise OIDCIdentityError("OIDC workflow resolution requires bindings and signed protected objects.")
    expected: dict[str, tuple[str, str, str]] = {}
    for document in protected_documents:
        if not isinstance(document, Mapping):
            raise OIDCIdentityError("Protected workflow object must be a JSON object.")
        schema = document.get("schema_version")
        if schema == "finredops.identity-assertion.v1":
            item = identity_assertion_from_document(document)
            object_id, subject, role, object_engagement = item.assertion_id, item.subject, item.role, item.engagement_id
        elif schema == "finredops.approval-signature.v1":
            item = approval_signature_from_document(document)
            object_id, subject, role, object_engagement = item.signature_id, item.subject, item.role, item.engagement_id
        else:
            raise OIDCIdentityError("Unsupported protected object in OIDC workflow resolution.")
        if object_engagement != engagement_id:
            raise OIDCIdentityError("Protected object is bound to a different engagement.")
        if object_id in expected:
            raise OIDCIdentityError("Duplicate protected identity object supplied.")
        expected[object_id] = (sha256_digest(document), subject, role)

    by_object: dict[str, OIDCIdentityBinding] = {}
    for binding in bindings:
        if binding.engagement_id != engagement_id or binding.protected_id in by_object:
            raise OIDCIdentityError("OIDC binding engagement mismatch or duplicate protected object.")
        by_object[binding.protected_id] = binding
    if set(by_object) != set(expected):
        raise OIDCIdentityError("OIDC bindings must exactly cover the supplied signed identity objects.")
    for object_id, (object_digest, subject, role) in expected.items():
        binding = by_object[object_id]
        if binding.protected_digest != object_digest or binding.subject != subject or binding.role != role:
            raise OIDCIdentityError("OIDC binding does not match its signed protected object.")

    return OIDCWorkflowResolution(
        engagement_id=engagement_id,
        binding_ids=tuple(sorted(item.binding_id for item in bindings)),
        protected_ids=tuple(sorted(expected)),
        verification_ids=tuple(sorted({item.verification_id for item in bindings})),
        subjects=tuple(sorted({item.subject for item in bindings})),
        roles=tuple(sorted({item.role for item in bindings})),
    )
