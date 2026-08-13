"""Key-backed approval signatures for risk acceptance and report approval.

This module extends FinRedOps' verification-only trust boundary. Private keys stay
outside FinRedOps. External signers produce Ed25519 signatures over deterministic,
short-lived approval envelopes; FinRedOps verifies them against configured public
keys before a trusted risk acceptance is consumed or a draft report is marked
approved.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature

from .intake import EvidenceIntakeBatch, read_intake_file
from .models import ensure_aware, parse_datetime, sha256_digest, to_primitive
from .reporting import AssessmentReport, ReportStatus, report_from_document, render_report_markdown, validate_report
from .review import QualifiedFindingReview, RiskAcceptance, read_review_json, review_from_document, risk_acceptance_from_document
from .trust import ReviewerTrustBundle, ReviewTrustError, trust_bundle_from_document

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SIGNATURE_ID = re.compile(r"^FRX-APS-[A-F0-9]{24}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_PURPOSE_ROLE = {
    "risk_acceptance": "business_risk_owner",
    "report_approval": "report_approver",
}
_OBJECT_TYPES = {
    "risk_acceptance": "risk_acceptance",
    "report_approval": "regulatory_report",
}
_CLOCK_SKEW_SECONDS = 300


class ApprovalTrustError(ReviewTrustError):
    """Raised when approval signature validation fails closed."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ApprovalTrustError(f"{name} is not a valid bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ApprovalTrustError(f"{name} must be a lowercase SHA-256 digest.")
    return value


def _decode(value: Any, name: str, length: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ApprovalTrustError(f"{name} must be non-empty base64url.")
    try:
        raw = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ApprovalTrustError(f"{name} is not valid base64url.") from exc
    if len(decoded) != length:
        raise ApprovalTrustError(f"{name} must decode to {length} bytes.")
    return decoded


def _canonical(value: Any) -> bytes:
    return json.dumps(
        to_primitive(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _derived_signature_id(core: Mapping[str, Any]) -> str:
    return f"FRX-APS-{sha256_digest(core)[:24].upper()}"


@dataclass(frozen=True, slots=True)
class ApprovalSignature:
    signature_id: str
    issuer: str
    subject: str
    key_id: str
    purpose: str
    role: str
    engagement_id: str
    object_type: str
    object_id: str
    object_digest: str
    context_digest: str
    issued_at: datetime
    expires_at: datetime
    signature: str
    algorithm: str = "Ed25519"

    def core(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "purpose": self.purpose,
            "role": self.role,
            "engagement_id": self.engagement_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "object_digest": self.object_digest,
            "context_digest": self.context_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def signing_document(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.approval-signature.v1",
            "signature_id": self.signature_id,
            **self.core(),
        }

    def signing_bytes(self) -> bytes:
        return _canonical(self.signing_document())

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self.signing_document()), "signature": self.signature}

    def __post_init__(self) -> None:
        if not _SIGNATURE_ID.fullmatch(self.signature_id):
            raise ApprovalTrustError("Invalid approval signature id.")
        for name in ("issuer", "subject", "key_id", "engagement_id", "object_type", "object_id"):
            _identifier(getattr(self, name), name)
        if self.algorithm != "Ed25519":
            raise ApprovalTrustError("Only Ed25519 approval signatures are supported.")
        expected_role = _PURPOSE_ROLE.get(self.purpose)
        expected_object = _OBJECT_TYPES.get(self.purpose)
        if expected_role is None or self.role != expected_role or self.object_type != expected_object:
            raise ApprovalTrustError("Approval purpose, role, or object type is invalid.")
        _digest(self.object_digest, "object_digest")
        _digest(self.context_digest, "context_digest")
        issued = ensure_aware(self.issued_at)
        expires = ensure_aware(self.expires_at)
        if expires <= issued or (expires - issued).total_seconds() > 86400:
            raise ApprovalTrustError("Approval signature validity must be >0 and <=24 hours.")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        _decode(self.signature, "signature", 64)
        if self.signature_id != _derived_signature_id(self.core()):
            raise ApprovalTrustError("Approval signature id does not match its payload.")


def approval_signature_signing_document(document: Any) -> dict[str, Any]:
    fields = {
        "issuer",
        "subject",
        "key_id",
        "algorithm",
        "purpose",
        "role",
        "engagement_id",
        "object_type",
        "object_id",
        "object_digest",
        "context_digest",
        "issued_at",
        "expires_at",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise ApprovalTrustError("Approval signature request does not match the v1 contract.")
    core = dict(document)
    core["issued_at"] = parse_datetime(str(core["issued_at"]))
    core["expires_at"] = parse_datetime(str(core["expires_at"]))
    purpose = str(core["purpose"])
    if _PURPOSE_ROLE.get(purpose) != str(core["role"]):
        raise ApprovalTrustError("Approval request role does not match its purpose.")
    if _OBJECT_TYPES.get(purpose) != str(core["object_type"]):
        raise ApprovalTrustError("Approval request object type does not match its purpose.")
    # Instantiate with a placeholder signature to reuse strict field/window validation.
    placeholder = ApprovalSignature(
        signature_id=_derived_signature_id(core),
        issuer=str(core["issuer"]),
        subject=str(core["subject"]),
        key_id=str(core["key_id"]),
        algorithm=str(core["algorithm"]),
        purpose=purpose,
        role=str(core["role"]),
        engagement_id=str(core["engagement_id"]),
        object_type=str(core["object_type"]),
        object_id=str(core["object_id"]),
        object_digest=str(core["object_digest"]),
        context_digest=str(core["context_digest"]),
        issued_at=core["issued_at"],
        expires_at=core["expires_at"],
        signature=base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("="),
    )
    return to_primitive(placeholder.signing_document())


def approval_signature_from_document(document: Any) -> ApprovalSignature:
    required = {
        "schema_version",
        "signature_id",
        "issuer",
        "subject",
        "key_id",
        "algorithm",
        "purpose",
        "role",
        "engagement_id",
        "object_type",
        "object_id",
        "object_digest",
        "context_digest",
        "issued_at",
        "expires_at",
        "signature",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise ApprovalTrustError("Approval signature does not match the v1 contract.")
    if document["schema_version"] != "finredops.approval-signature.v1":
        raise ApprovalTrustError("Unsupported approval signature schema.")
    return ApprovalSignature(
        signature_id=str(document["signature_id"]),
        issuer=str(document["issuer"]),
        subject=str(document["subject"]),
        key_id=str(document["key_id"]),
        algorithm=str(document["algorithm"]),
        purpose=str(document["purpose"]),
        role=str(document["role"]),
        engagement_id=str(document["engagement_id"]),
        object_type=str(document["object_type"]),
        object_id=str(document["object_id"]),
        object_digest=str(document["object_digest"]),
        context_digest=str(document["context_digest"]),
        issued_at=parse_datetime(str(document["issued_at"])),
        expires_at=parse_datetime(str(document["expires_at"])),
        signature=str(document["signature"]),
    )


def verify_approval_signature(
    approval: ApprovalSignature,
    bundle: ReviewerTrustBundle,
    *,
    purpose: str,
    engagement_id: str,
    object_id: str,
    object_digest: str,
    context_digest: str,
    subject: str,
    as_of: datetime,
) -> None:
    expected_role = _PURPOSE_ROLE.get(purpose)
    expected_object = _OBJECT_TYPES.get(purpose)
    if expected_role is None or expected_object is None:
        raise ApprovalTrustError("Unsupported approval purpose.")
    key = bundle.get(approval.issuer, approval.key_id)
    effective = ensure_aware(as_of)
    checks = (
        (approval.algorithm == key.algorithm, "algorithm"),
        (approval.purpose == purpose, "purpose"),
        (approval.role == expected_role and expected_role in key.roles, "role"),
        (approval.engagement_id == engagement_id, "engagement"),
        (approval.object_type == expected_object, "object-type"),
        (approval.object_id == object_id and approval.object_digest == object_digest, "object"),
        (approval.context_digest == context_digest, "context"),
        (approval.subject == subject, "subject"),
        (key.not_before <= effective <= key.not_after, "trust-key validity"),
        (effective.timestamp() + _CLOCK_SKEW_SECONDS >= approval.issued_at.timestamp(), "not-before"),
        (effective.timestamp() - _CLOCK_SKEW_SECONDS <= approval.expires_at.timestamp(), "expiry"),
    )
    failed = [name for valid, name in checks if not valid]
    if failed:
        raise ApprovalTrustError(f"Approval signature binding failed: {', '.join(failed)}.")
    try:
        key.verifier().verify(_decode(approval.signature, "signature", 64), approval.signing_bytes())
    except InvalidSignature as exc:
        raise ApprovalTrustError("Approval signature verification failed.") from exc


@dataclass(frozen=True, slots=True)
class SignedRiskAcceptanceResolution:
    engagement_id: str
    trust_bundle_digest: str
    trust_resolution_digest: str
    acceptance_ids: tuple[str, ...]
    acceptance_digests: tuple[str, ...]
    signature_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.signed-risk-acceptance-resolution.v1",
            "engagement_id": self.engagement_id,
            "trust_bundle_digest": self.trust_bundle_digest,
            "trust_resolution_digest": self.trust_resolution_digest,
            "acceptance_ids": list(self.acceptance_ids),
            "acceptance_digests": list(self.acceptance_digests),
            "signature_ids": list(self.signature_ids),
            "cryptographic_signatures_verified": True,
            "signature_algorithm": "Ed25519",
        }
        return {**body, "resolution_digest": sha256_digest(body)}


def verify_signed_risk_acceptances(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptances: Sequence[RiskAcceptance],
    signatures: Sequence[ApprovalSignature],
    bundle: ReviewerTrustBundle,
    *,
    engagement_id: str,
    trust_resolution_digest: str,
    as_of: datetime,
) -> SignedRiskAcceptanceResolution:
    _identifier(engagement_id, "engagement_id")
    _digest(trust_resolution_digest, "trust_resolution_digest")
    by_finding = {item.finding_id: item for item in reviews}
    if len(by_finding) != len(reviews):
        raise ApprovalTrustError("Authoritative reviews must be unique per finding.")
    acceptance_by_id = {item.acceptance_id: item for item in acceptances}
    if len(acceptance_by_id) != len(acceptances):
        raise ApprovalTrustError("Duplicate risk acceptances were supplied.")
    signature_by_object = {
        item.object_id: item for item in signatures if item.purpose == "risk_acceptance"
    }
    if len(signature_by_object) != len(signatures):
        raise ApprovalTrustError("Risk-acceptance signatures must be unique and purpose-bound.")
    if set(signature_by_object) != set(acceptance_by_id):
        raise ApprovalTrustError("Signed risk-acceptance set must exactly cover supplied acceptances.")

    for acceptance in acceptances:
        review = by_finding.get(acceptance.finding_id)
        if review is None:
            raise ApprovalTrustError("Risk acceptance has no current authoritative review.")
        if acceptance.batch_id != batch.batch_id or acceptance.batch_digest != batch.digest():
            raise ApprovalTrustError("Risk acceptance is bound to a different intake batch.")
        if acceptance.review_id != review.review_id or acceptance.review_digest != review.digest():
            raise ApprovalTrustError("Risk acceptance is bound to a non-authoritative review.")
        signature = signature_by_object[acceptance.acceptance_id]
        verify_approval_signature(
            signature,
            bundle,
            purpose="risk_acceptance",
            engagement_id=engagement_id,
            object_id=acceptance.acceptance_id,
            object_digest=acceptance.digest(),
            context_digest=trust_resolution_digest,
            subject=acceptance.accepted_by,
            as_of=as_of,
        )

    return SignedRiskAcceptanceResolution(
        engagement_id=engagement_id,
        trust_bundle_digest=bundle.digest(),
        trust_resolution_digest=trust_resolution_digest,
        acceptance_ids=tuple(sorted(acceptance_by_id)),
        acceptance_digests=tuple(sorted(item.digest() for item in acceptances)),
        signature_ids=tuple(sorted(item.signature_id for item in signatures)),
    )


def load_verified_risk_acceptances(
    *,
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptance_paths: Sequence[Path],
    signature_paths: Sequence[Path],
    trust_bundle_path: Path,
    engagement_id: str,
    trust_resolution_digest: str,
    as_of: datetime,
) -> tuple[tuple[RiskAcceptance, ...], SignedRiskAcceptanceResolution]:
    by_finding = {item.finding_id: item for item in reviews}
    acceptances: list[RiskAcceptance] = []
    for path in acceptance_paths:
        document = read_review_json(path)
        if not isinstance(document, Mapping):
            raise ApprovalTrustError("Risk acceptance must be an object.")
        review = by_finding.get(str(document.get("finding_id", "")))
        if review is None:
            raise ApprovalTrustError("Risk acceptance has no supplied current authoritative review.")
        acceptances.append(risk_acceptance_from_document(document, batch, review))
    signatures = tuple(
        approval_signature_from_document(read_review_json(path)) for path in signature_paths
    )
    bundle = trust_bundle_from_document(read_review_json(trust_bundle_path))
    resolution = verify_signed_risk_acceptances(
        batch,
        reviews,
        tuple(acceptances),
        signatures,
        bundle,
        engagement_id=engagement_id,
        trust_resolution_digest=trust_resolution_digest,
        as_of=as_of,
    )
    return tuple(acceptances), resolution


def _trusted_promotion_manifest(document: Any) -> dict[str, str]:
    required = {
        "schema_version",
        "base_promotion_digest",
        "report_id",
        "report_digest",
        "engagement_id",
        "trust_resolution_digest",
        "trust_bundle_digest",
        "cryptographic_signatures_verified",
        "signature_algorithm",
        "report_issued",
        "human_approval_required",
        "trusted_promotion_digest",
    }
    optional = {
        "risk_acceptance_resolution_digest",
        "risk_acceptance_signature_count",
    }
    if not isinstance(document, Mapping) or not required.issubset(document) or (set(document) - required - optional):
        raise ApprovalTrustError("Trusted-promotion manifest does not match the supported contract.")
    if document["schema_version"] != "finredops.trusted-report-promotion.v1":
        raise ApprovalTrustError("Unsupported trusted-promotion manifest schema.")
    body = {key: document[key] for key in document if key != "trusted_promotion_digest"}
    if sha256_digest(body) != document["trusted_promotion_digest"]:
        raise ApprovalTrustError("Trusted-promotion manifest digest is invalid.")
    if document["cryptographic_signatures_verified"] is not True or document["report_issued"] is not False:
        raise ApprovalTrustError("Trusted-promotion manifest does not preserve the trust boundary.")
    for name in ("report_digest", "trust_resolution_digest", "trust_bundle_digest", "trusted_promotion_digest"):
        _digest(document[name], name)
    return {key: str(value) for key, value in document.items() if isinstance(value, str)}


@dataclass(frozen=True, slots=True)
class SignedReportApprovalResolution:
    engagement_id: str
    trust_bundle_digest: str
    trusted_promotion_digest: str
    source_report_digest: str
    approved_report_digest: str
    signature_ids: tuple[str, ...]
    approvers: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema_version": "finredops.signed-report-approval.v1",
            "engagement_id": self.engagement_id,
            "trust_bundle_digest": self.trust_bundle_digest,
            "trusted_promotion_digest": self.trusted_promotion_digest,
            "source_report_digest": self.source_report_digest,
            "approved_report_digest": self.approved_report_digest,
            "signature_ids": list(self.signature_ids),
            "approvers": list(self.approvers),
            "cryptographic_signatures_verified": True,
            "signature_algorithm": "Ed25519",
            "report_status": "approved",
            "report_issued": False,
        }
        return {**body, "approval_resolution_digest": sha256_digest(body)}


def approve_report_with_signatures(
    report: AssessmentReport,
    signatures: Sequence[ApprovalSignature],
    bundle: ReviewerTrustBundle,
    trusted_manifest: Mapping[str, Any],
    *,
    engagement_id: str,
    as_of: datetime,
) -> tuple[AssessmentReport, SignedReportApprovalResolution]:
    manifest = _trusted_promotion_manifest(trusted_manifest)
    if report.status != ReportStatus.DRAFT or report.human_approvals:
        raise ApprovalTrustError("Signed approval requires the untouched trusted draft report.")
    if manifest.get("report_id") != report.report_id or manifest.get("report_digest") != report.digest():
        raise ApprovalTrustError("Trusted-promotion manifest does not match the draft report.")
    if manifest.get("engagement_id") != engagement_id:
        raise ApprovalTrustError("Trusted-promotion manifest is bound to a different engagement.")
    if manifest.get("trust_bundle_digest") != bundle.digest():
        raise ApprovalTrustError("Approval trust bundle differs from the trusted-promotion bundle.")
    if len(signatures) != 2:
        raise ApprovalTrustError("Report approval requires exactly two signed approval records.")
    if len({item.signature_id for item in signatures}) != 2 or len({item.subject for item in signatures}) != 2:
        raise ApprovalTrustError("Report approval requires two distinct signatures from two distinct people.")

    for signature in signatures:
        verify_approval_signature(
            signature,
            bundle,
            purpose="report_approval",
            engagement_id=engagement_id,
            object_id=report.report_id,
            object_digest=report.digest(),
            context_digest=manifest["trusted_promotion_digest"],
            subject=signature.subject,
            as_of=as_of,
        )

    signature_ids = tuple(sorted(item.signature_id for item in signatures))
    approved = replace(
        report,
        status=ReportStatus.APPROVED,
        human_approvals=signature_ids,
    )
    validation = validate_report(approved)
    if not validation.valid or not validation.ready_for_issue:
        raise ApprovalTrustError("Cryptographically approved report failed structural readiness validation.")
    resolution = SignedReportApprovalResolution(
        engagement_id=engagement_id,
        trust_bundle_digest=bundle.digest(),
        trusted_promotion_digest=manifest["trusted_promotion_digest"],
        source_report_digest=report.digest(),
        approved_report_digest=approved.digest(),
        signature_ids=signature_ids,
        approvers=tuple(sorted(item.subject for item in signatures)),
    )
    return approved, resolution


def load_and_approve_report(
    *,
    report_path: Path,
    trusted_manifest_path: Path,
    signature_paths: Sequence[Path],
    trust_bundle_path: Path,
    engagement_id: str,
    as_of: datetime,
) -> tuple[AssessmentReport, SignedReportApprovalResolution]:
    report = report_from_document(read_review_json(report_path))
    manifest = read_review_json(trusted_manifest_path)
    signatures = tuple(
        approval_signature_from_document(read_review_json(path)) for path in signature_paths
    )
    bundle = trust_bundle_from_document(read_review_json(trust_bundle_path))
    return approve_report_with_signatures(
        report,
        signatures,
        bundle,
        manifest,
        engagement_id=engagement_id,
        as_of=as_of,
    )


def write_approved_report_outputs(
    output_dir: Path,
    report: AssessmentReport,
    resolution: SignedReportApprovalResolution,
) -> None:
    if output_dir.exists() and not output_dir.is_dir():
        raise ApprovalTrustError("output-dir must be a directory path.")
    names = (
        "approved-regulatory-report.json",
        "approved-regulatory-report.md",
        "signed-report-approval.json",
    )
    collisions = [name for name in names if (output_dir / name).exists()]
    if collisions:
        raise ApprovalTrustError(f"Refusing to overwrite signed approval outputs: {collisions}.")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / names[0]).write_text(
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / names[1]).write_text(render_report_markdown(report), encoding="utf-8")
    (output_dir / names[2]).write_text(
        json.dumps(resolution.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
