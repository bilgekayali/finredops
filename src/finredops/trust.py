"""Ed25519 reviewer identity verification and immutable review lifecycle resolution."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .intake import EvidenceIntakeBatch, read_intake_file
from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .review import (
    QualifiedFindingReview,
    RiskAcceptance,
    read_review_json,
    review_from_document,
    risk_acceptance_from_document,
)

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_REVIEW_ID = re.compile(r"^FRX-REV-[A-F0-9]{24}$")
_ASSERTION_ID = re.compile(r"^FRX-IDN-[A-F0-9]{24}$")
_EVENT_ID = re.compile(r"^FRX-RLC-[A-F0-9]{24}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_ROLES = {"qualified_tester", "review_governor"}
_PURPOSES = {"finding_review", "review_lifecycle"}
_CLOCK_SKEW_SECONDS = 300


class ReviewTrustError(ValueError):
    """Raised when signed identity or lifecycle validation fails closed."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ReviewTrustError(f"{name} is not a valid bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ReviewTrustError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _decode(value: Any, name: str, length: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ReviewTrustError(f"{name} must be non-empty base64url.")
    try:
        raw = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ReviewTrustError(f"{name} is not valid base64url.") from exc
    if len(decoded) != length:
        raise ReviewTrustError(f"{name} must decode to {length} bytes.")
    return decoded


def _canonical(value: Any) -> bytes:
    return json.dumps(
        to_primitive(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _derived_id(prefix: str, digest: str) -> str:
    return f"{prefix}-{digest[:24].upper()}"


@dataclass(frozen=True, slots=True)
class ReviewerTrustKey:
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
            raise ReviewTrustError("Only Ed25519 reviewer trust keys are supported.")
        _decode(self.public_key, "public_key", 32)
        if not self.roles or any(role not in _ROLES for role in self.roles):
            raise ReviewTrustError("Trust key roles are invalid.")
        object.__setattr__(self, "roles", tuple(sorted(set(self.roles))))
        start, end = ensure_aware(self.not_before), ensure_aware(self.not_after)
        if end <= start:
            raise ReviewTrustError("Trust key validity window is invalid.")
        object.__setattr__(self, "not_before", start)
        object.__setattr__(self, "not_after", end)

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_decode(self.public_key, "public_key", 32))


@dataclass(frozen=True, slots=True)
class ReviewerTrustBundle:
    bundle_id: str
    keys: tuple[ReviewerTrustKey, ...]

    def __post_init__(self) -> None:
        _identifier(self.bundle_id, "bundle_id")
        identities = [(item.issuer, item.key_id) for item in self.keys]
        if not self.keys or len(set(identities)) != len(identities):
            raise ReviewTrustError("Trust bundle keys must be non-empty and unique.")

    def digest(self) -> str:
        return sha256_digest(
            {
                "schema_version": "finredops.reviewer-trust-bundle.v1",
                "bundle_id": self.bundle_id,
                "keys": [to_primitive(item) for item in self.keys],
            }
        )

    def get(self, issuer: str, key_id: str) -> ReviewerTrustKey:
        matches = [item for item in self.keys if item.issuer == issuer and item.key_id == key_id]
        if len(matches) != 1:
            raise ReviewTrustError("Identity assertion references an unknown trust key.")
        return matches[0]


def trust_bundle_from_document(document: Any) -> ReviewerTrustBundle:
    if not isinstance(document, Mapping) or set(document) != {
        "schema_version", "bundle_id", "keys"
    }:
        raise ReviewTrustError("Reviewer trust bundle does not match the v1 contract.")
    if document["schema_version"] != "finredops.reviewer-trust-bundle.v1":
        raise ReviewTrustError("Unsupported reviewer trust bundle schema.")
    raw_keys = document["keys"]
    if not isinstance(raw_keys, list):
        raise ReviewTrustError("Trust bundle keys must be an array.")
    fields = {"issuer", "key_id", "algorithm", "public_key", "roles", "not_before", "not_after"}
    keys: list[ReviewerTrustKey] = []
    for raw in raw_keys:
        if not isinstance(raw, Mapping) or set(raw) != fields or not isinstance(raw["roles"], list):
            raise ReviewTrustError("Reviewer trust key does not match the v1 contract.")
        keys.append(
            ReviewerTrustKey(
                issuer=str(raw["issuer"]),
                key_id=str(raw["key_id"]),
                algorithm=str(raw["algorithm"]),
                public_key=str(raw["public_key"]),
                roles=tuple(str(item) for item in raw["roles"]),
                not_before=parse_datetime(str(raw["not_before"])),
                not_after=parse_datetime(str(raw["not_after"])),
            )
        )
    return ReviewerTrustBundle(str(document["bundle_id"]), tuple(keys))


@dataclass(frozen=True, slots=True)
class ReviewLifecycleEvent:
    event_id: str
    batch_id: str
    batch_digest: str
    finding_id: str
    action: str
    prior_review_id: str
    prior_review_digest: str
    replacement_review_id: str
    replacement_review_digest: str
    actor_id: str
    event_at: datetime
    reason: str

    def payload(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "batch_digest": self.batch_digest,
            "finding_id": self.finding_id,
            "action": self.action,
            "prior_review_id": self.prior_review_id,
            "prior_review_digest": self.prior_review_digest,
            "replacement_review_id": self.replacement_review_id,
            "replacement_review_digest": self.replacement_review_digest,
            "actor_id": self.actor_id,
            "event_at": self.event_at,
            "reason": self.reason,
        }

    def payload_digest(self) -> str:
        return sha256_digest(self.payload())

    def digest(self) -> str:
        return sha256_digest({"event_id": self.event_id, **self.payload()})

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.review-lifecycle-event.v1",
            "event_id": self.event_id,
            **to_primitive(self.payload()),
            "event_digest": self.digest(),
        }

    def __post_init__(self) -> None:
        if not _EVENT_ID.fullmatch(self.event_id):
            raise ReviewTrustError("Invalid lifecycle event id.")
        _identifier(self.batch_id, "batch_id")
        _digest(self.batch_digest, "batch_digest")
        _identifier(self.finding_id, "finding_id")
        _identifier(self.actor_id, "actor_id")
        if self.action not in {"supersede", "revoke"}:
            raise ReviewTrustError("Lifecycle action must be supersede or revoke.")
        if not _REVIEW_ID.fullmatch(self.prior_review_id):
            raise ReviewTrustError("Invalid prior review id.")
        _digest(self.prior_review_digest, "prior_review_digest")
        if self.action == "supersede":
            if not _REVIEW_ID.fullmatch(self.replacement_review_id):
                raise ReviewTrustError("Supersession requires a replacement review.")
            _digest(self.replacement_review_digest, "replacement_review_digest")
            if self.replacement_review_id == self.prior_review_id:
                raise ReviewTrustError("A review cannot supersede itself.")
        elif self.replacement_review_id or self.replacement_review_digest:
            raise ReviewTrustError("Revocation cannot name a replacement review.")
        object.__setattr__(self, "event_at", ensure_aware(self.event_at))
        if not isinstance(self.reason, str) or not 20 <= len(self.reason.strip()) <= 4000:
            raise ReviewTrustError("Lifecycle reason must contain 20 to 4000 characters.")
        if self.event_id != _derived_id("FRX-RLC", self.payload_digest()):
            raise ReviewTrustError("Lifecycle event id does not match its immutable payload.")


def lifecycle_event_from_draft(document: Any) -> ReviewLifecycleEvent:
    fields = {
        "batch_id", "batch_digest", "finding_id", "action",
        "prior_review_id", "prior_review_digest", "replacement_review_id",
        "replacement_review_digest", "actor_id", "event_at", "reason",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise ReviewTrustError("Review lifecycle draft does not match the v1 contract.")
    payload = dict(document)
    payload["event_at"] = parse_datetime(str(payload["event_at"]))
    return ReviewLifecycleEvent(
        event_id=_derived_id("FRX-RLC", sha256_digest(payload)),
        batch_id=str(payload["batch_id"]),
        batch_digest=str(payload["batch_digest"]),
        finding_id=str(payload["finding_id"]),
        action=str(payload["action"]),
        prior_review_id=str(payload["prior_review_id"]),
        prior_review_digest=str(payload["prior_review_digest"]),
        replacement_review_id=str(payload["replacement_review_id"]),
        replacement_review_digest=str(payload["replacement_review_digest"]),
        actor_id=str(payload["actor_id"]),
        event_at=payload["event_at"],
        reason=str(payload["reason"]),
    )


def lifecycle_event_from_document(document: Any) -> ReviewLifecycleEvent:
    required = {
        "schema_version", "event_id", "batch_id", "batch_digest", "finding_id", "action",
        "prior_review_id", "prior_review_digest", "replacement_review_id",
        "replacement_review_digest", "actor_id", "event_at", "reason", "event_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ReviewTrustError("Review lifecycle document does not match the v1 contract.")
    if document["schema_version"] != "finredops.review-lifecycle-event.v1":
        raise ReviewTrustError("Unsupported lifecycle event schema.")
    event = lifecycle_event_from_draft(
        {key: document[key] for key in required - {"schema_version", "event_id", "event_digest"}}
    )
    if event.event_id != document["event_id"] or event.digest() != document["event_digest"]:
        raise ReviewTrustError("Review lifecycle identifier or digest is invalid.")
    return event


@dataclass(frozen=True, slots=True)
class SignedIdentityAssertion:
    assertion_id: str
    issuer: str
    subject: str
    key_id: str
    purpose: str
    role: str
    engagement_id: str
    batch_id: str
    batch_digest: str
    finding_id: str
    object_id: str
    object_digest: str
    issued_at: datetime
    expires_at: datetime
    signature: str
    algorithm: str = "Ed25519"

    def core(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer, "subject": self.subject, "key_id": self.key_id,
            "algorithm": self.algorithm, "purpose": self.purpose, "role": self.role,
            "engagement_id": self.engagement_id, "batch_id": self.batch_id,
            "batch_digest": self.batch_digest, "finding_id": self.finding_id,
            "object_id": self.object_id, "object_digest": self.object_digest,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
        }

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.identity-assertion.v1",
            "assertion_id": self.assertion_id,
            **self.core(),
        }

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_document())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.signing_document()), "signature": self.signature}

    def __post_init__(self) -> None:
        if not _ASSERTION_ID.fullmatch(self.assertion_id):
            raise ReviewTrustError("Invalid identity assertion id.")
        for name in ("issuer", "subject", "key_id", "engagement_id", "batch_id", "finding_id", "object_id"):
            _identifier(getattr(self, name), name)
        if self.algorithm != "Ed25519" or self.purpose not in _PURPOSES or self.role not in _ROLES:
            raise ReviewTrustError("Identity assertion algorithm, purpose, or role is invalid.")
        _digest(self.batch_digest, "batch_digest")
        _digest(self.object_digest, "object_digest")
        issued, expires = ensure_aware(self.issued_at), ensure_aware(self.expires_at)
        if expires <= issued or (expires - issued).total_seconds() > 86400:
            raise ReviewTrustError("Identity assertion validity must be >0 and <=24 hours.")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        _decode(self.signature, "signature", 64)
        if self.assertion_id != _derived_id("FRX-IDN", sha256_digest(self.core())):
            raise ReviewTrustError("Identity assertion id does not match its payload.")


def identity_assertion_signing_document(document: Any) -> dict[str, Any]:
    fields = {
        "issuer", "subject", "key_id", "algorithm", "purpose", "role",
        "engagement_id", "batch_id", "batch_digest", "finding_id", "object_id",
        "object_digest", "issued_at", "expires_at",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise ReviewTrustError("Identity assertion request does not match the v1 contract.")
    core = dict(document)
    core["issued_at"] = parse_datetime(str(core["issued_at"]))
    core["expires_at"] = parse_datetime(str(core["expires_at"]))
    return to_primitive(
        {
            "schema_version": "finredops.identity-assertion.v1",
            "assertion_id": _derived_id("FRX-IDN", sha256_digest(core)),
            **core,
        }
    )


def identity_assertion_from_document(document: Any) -> SignedIdentityAssertion:
    required = {
        "schema_version", "assertion_id", "issuer", "subject", "key_id", "algorithm",
        "purpose", "role", "engagement_id", "batch_id", "batch_digest", "finding_id",
        "object_id", "object_digest", "issued_at", "expires_at", "signature",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ReviewTrustError("Identity assertion does not match the v1 contract.")
    if document["schema_version"] != "finredops.identity-assertion.v1":
        raise ReviewTrustError("Unsupported identity assertion schema.")
    return SignedIdentityAssertion(
        assertion_id=str(document["assertion_id"]), issuer=str(document["issuer"]),
        subject=str(document["subject"]), key_id=str(document["key_id"]),
        algorithm=str(document["algorithm"]), purpose=str(document["purpose"]),
        role=str(document["role"]), engagement_id=str(document["engagement_id"]),
        batch_id=str(document["batch_id"]), batch_digest=str(document["batch_digest"]),
        finding_id=str(document["finding_id"]), object_id=str(document["object_id"]),
        object_digest=str(document["object_digest"]),
        issued_at=parse_datetime(str(document["issued_at"])),
        expires_at=parse_datetime(str(document["expires_at"])),
        signature=str(document["signature"]),
    )


def verify_assertion(
    assertion: SignedIdentityAssertion,
    bundle: ReviewerTrustBundle,
    *,
    engagement_id: str,
    batch: EvidenceIntakeBatch,
    finding_id: str,
    object_id: str,
    object_digest: str,
    purpose: str,
    role: str,
    subject: str,
    as_of: datetime,
) -> None:
    key = bundle.get(assertion.issuer, assertion.key_id)
    effective = ensure_aware(as_of)
    checks = (
        (assertion.algorithm == key.algorithm, "algorithm"),
        (assertion.role == role and role in key.roles, "role"),
        (assertion.purpose == purpose, "purpose"),
        (assertion.engagement_id == engagement_id, "engagement"),
        (assertion.batch_id == batch.batch_id and assertion.batch_digest == batch.digest(), "intake"),
        (assertion.finding_id == finding_id, "finding"),
        (assertion.object_id == object_id and assertion.object_digest == object_digest, "object"),
        (assertion.subject == subject, "subject"),
        (key.not_before <= effective <= key.not_after, "trust-key validity"),
        (effective.timestamp() + _CLOCK_SKEW_SECONDS >= assertion.issued_at.timestamp(), "not-before"),
        (effective.timestamp() - _CLOCK_SKEW_SECONDS <= assertion.expires_at.timestamp(), "expiry"),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ReviewTrustError(f"Identity assertion binding failed: {', '.join(failed)}.")
    try:
        key.verifier().verify(_decode(assertion.signature, "signature", 64), assertion.signing_bytes())
    except InvalidSignature as exc:
        raise ReviewTrustError("Identity assertion signature verification failed.") from exc


@dataclass(frozen=True, slots=True)
class TrustedReviewResolution:
    engagement_id: str
    trust_bundle_digest: str
    authoritative_reviews: tuple[QualifiedFindingReview, ...]
    revoked_finding_ids: tuple[str, ...]
    verified_assertion_ids: tuple[str, ...]
    lifecycle_event_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.trusted-review-resolution.v1",
            "engagement_id": self.engagement_id,
            "trust_bundle_digest": self.trust_bundle_digest,
            "authoritative_review_ids": [item.review_id for item in self.authoritative_reviews],
            "revoked_finding_ids": list(self.revoked_finding_ids),
            "verified_assertion_ids": list(self.verified_assertion_ids),
            "lifecycle_event_ids": list(self.lifecycle_event_ids),
            "cryptographic_signatures_verified": True,
            "signature_algorithm": "Ed25519",
            "external_idp_protocol_verified": False,
        }
        return {**body, "resolution_digest": sha256_digest(body)}


def resolve_trusted_reviews(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    events: Sequence[ReviewLifecycleEvent],
    assertions: Sequence[SignedIdentityAssertion],
    bundle: ReviewerTrustBundle,
    *,
    engagement_id: str,
    as_of: datetime,
) -> TrustedReviewResolution:
    _identifier(engagement_id, "engagement_id")
    review_by_id = {item.review_id: item for item in reviews}
    event_by_id = {item.event_id: item for item in events}
    if len(review_by_id) != len(reviews) or len(event_by_id) != len(events):
        raise ReviewTrustError("Duplicate review or lifecycle documents were supplied.")
    if any(item.batch_id != batch.batch_id or item.batch_digest != batch.digest() for item in reviews):
        raise ReviewTrustError("Review history is bound to a different intake batch.")

    assertion_map: dict[tuple[str, str], SignedIdentityAssertion] = {}
    for item in assertions:
        key = (item.purpose, item.object_id)
        if key in assertion_map:
            raise ReviewTrustError("Duplicate identity assertion for one protected object.")
        assertion_map[key] = item

    verified: list[str] = []
    for review in reviews:
        assertion = assertion_map.get(("finding_review", review.review_id))
        if assertion is None:
            raise ReviewTrustError(f"Review {review.review_id} lacks a signed identity assertion.")
        verify_assertion(
            assertion, bundle, engagement_id=engagement_id, batch=batch,
            finding_id=review.finding_id, object_id=review.review_id,
            object_digest=review.digest(), purpose="finding_review",
            role="qualified_tester", subject=review.reviewer_id, as_of=as_of,
        )
        verified.append(assertion.assertion_id)

    for event in events:
        if event.batch_id != batch.batch_id or event.batch_digest != batch.digest():
            raise ReviewTrustError("Lifecycle event is bound to a different intake batch.")
        assertion = assertion_map.get(("review_lifecycle", event.event_id))
        if assertion is None:
            raise ReviewTrustError(f"Lifecycle event {event.event_id} lacks a signed identity assertion.")
        verify_assertion(
            assertion, bundle, engagement_id=engagement_id, batch=batch,
            finding_id=event.finding_id, object_id=event.event_id,
            object_digest=event.digest(), purpose="review_lifecycle",
            role="review_governor", subject=event.actor_id, as_of=as_of,
        )
        verified.append(assertion.assertion_id)

    expected_assertions = {
        *(("finding_review", item.review_id) for item in reviews),
        *(("review_lifecycle", item.event_id) for item in events),
    }
    if set(assertion_map) != expected_assertions:
        raise ReviewTrustError("Identity assertion set must exactly cover supplied review history.")

    grouped_reviews: dict[str, list[QualifiedFindingReview]] = {}
    grouped_events: dict[str, list[ReviewLifecycleEvent]] = {}
    for item in reviews:
        grouped_reviews.setdefault(item.finding_id, []).append(item)
    for item in events:
        grouped_events.setdefault(item.finding_id, []).append(item)
    if set(grouped_events) - set(grouped_reviews):
        raise ReviewTrustError("Lifecycle events reference findings without review history.")

    authoritative: list[QualifiedFindingReview] = []
    revoked: list[str] = []
    for finding_id, history in grouped_reviews.items():
        by_id = {item.review_id: item for item in history}
        outgoing: dict[str, ReviewLifecycleEvent] = {}
        incoming: dict[str, ReviewLifecycleEvent] = {}
        for event in grouped_events.get(finding_id, []):
            prior = by_id.get(event.prior_review_id)
            if prior is None or prior.digest() != event.prior_review_digest:
                raise ReviewTrustError("Lifecycle event references an unknown or altered prior review.")
            if event.event_at < prior.reviewed_at or event.prior_review_id in outgoing:
                raise ReviewTrustError("Lifecycle chronology is invalid or branches.")
            outgoing[event.prior_review_id] = event
            if event.action == "supersede":
                replacement = by_id.get(event.replacement_review_id)
                if replacement is None or replacement.digest() != event.replacement_review_digest:
                    raise ReviewTrustError("Supersession references an unknown or altered replacement.")
                if replacement.reviewed_at < prior.reviewed_at or event.event_at < replacement.reviewed_at:
                    raise ReviewTrustError("Supersession chronology is not monotonic.")
                if replacement.review_id in incoming:
                    raise ReviewTrustError("Review history has multiple predecessors.")
                incoming[replacement.review_id] = event

        roots = [item for item in history if item.review_id not in incoming]
        if len(roots) != 1:
            raise ReviewTrustError("Review history must form one linear supersession chain.")
        current: QualifiedFindingReview | None = roots[0]
        visited: set[str] = set()
        while current is not None:
            if current.review_id in visited:
                raise ReviewTrustError("Review lifecycle contains a cycle.")
            visited.add(current.review_id)
            transition = outgoing.get(current.review_id)
            if transition is None:
                break
            current = None if transition.action == "revoke" else by_id[transition.replacement_review_id]
        if visited != set(by_id):
            raise ReviewTrustError("Review history contains an orphan or parallel review.")
        if current is None:
            revoked.append(finding_id)
        else:
            authoritative.append(current)

    return TrustedReviewResolution(
        engagement_id=engagement_id,
        trust_bundle_digest=bundle.digest(),
        authoritative_reviews=tuple(sorted(authoritative, key=lambda item: item.finding_id)),
        revoked_finding_ids=tuple(sorted(revoked)),
        verified_assertion_ids=tuple(sorted(verified)),
        lifecycle_event_ids=tuple(sorted(event_by_id)),
    )


def load_trusted_review_resolution(
    *,
    intake_path: Path,
    review_paths: Sequence[Path],
    lifecycle_paths: Sequence[Path],
    assertion_paths: Sequence[Path],
    trust_bundle_path: Path,
    engagement_id: str,
    as_of: datetime,
) -> tuple[EvidenceIntakeBatch, TrustedReviewResolution]:
    batch = read_intake_file(intake_path)
    reviews = tuple(review_from_document(read_review_json(path), batch) for path in review_paths)
    events = tuple(lifecycle_event_from_document(read_review_json(path)) for path in lifecycle_paths)
    assertions = tuple(identity_assertion_from_document(read_review_json(path)) for path in assertion_paths)
    bundle = trust_bundle_from_document(read_review_json(trust_bundle_path))
    return batch, resolve_trusted_reviews(
        batch, reviews, events, assertions, bundle,
        engagement_id=engagement_id, as_of=as_of,
    )


def load_acceptances_for_authoritative_reviews(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptance_paths: Sequence[Path],
) -> tuple[RiskAcceptance, ...]:
    by_finding = {item.finding_id: item for item in reviews}
    loaded: list[RiskAcceptance] = []
    for path in acceptance_paths:
        document = read_review_json(path)
        if not isinstance(document, Mapping):
            raise ReviewTrustError("Risk acceptance must be an object.")
        review = by_finding.get(str(document.get("finding_id", "")))
        if review is None:
            raise ReviewTrustError("Risk acceptance does not reference a current authoritative review.")
        loaded.append(risk_acceptance_from_document(document, batch, review))
    return tuple(loaded)
