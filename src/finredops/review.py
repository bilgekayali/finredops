"""Digest-bound qualified review and governed disposition of finding candidates.

Machine findings remain immutable inputs.  This module records a qualified
tester assessment, keeps business risk acceptance as a separate role-bound
decision, and builds a deterministic review summary without promoting anything
to a final penetration-test report.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evidence import EvidenceGuard
from .intake import CanonicalFinding, EvidenceIntakeBatch
from .models import StringEnum, ensure_aware, parse_datetime, sha256_digest, to_primitive
from .regulations import AssessmentType, turkey_financial_regulatory_profile


MAXIMUM_REVIEWS = 20_000
MAXIMUM_TEXT = 4_000
MAXIMUM_REFERENCES = 128
MAXIMUM_REVIEW_BYTES = 2_000_000
MAXIMUM_REVIEW_DEPTH = 32
MAXIMUM_REVIEW_NODES = 100_000

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_REVIEW_ID = re.compile(r"^FRX-REV-[A-F0-9]{24}$")
_ACCEPTANCE_ID = re.compile(r"^FRX-RISK-[A-F0-9]{24}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EVIDENCE_PREFIXES = ("evidence://", "attachment://", "qualification-evidence://")


class ReviewDocumentError(ValueError):
    """Raised when a review document violates the strict assurance contract."""


class ReviewDisposition(StringEnum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"


class ReviewerRole(StringEnum):
    QUALIFIED_TESTER = "qualified_tester"


class RiskAcceptanceRole(StringEnum):
    BUSINESS_RISK_OWNER = "business_risk_owner"


class FinalSeverity(StringEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewOutcome(StringEnum):
    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    ACCEPTED_RISK = "accepted_risk"


class RiskAcceptanceStatus(StringEnum):
    NONE = "none"
    ACTIVE = "active"
    EXPIRED = "expired"


def read_review_json(
    path: Path, *, maximum_bytes: int = MAXIMUM_REVIEW_BYTES
) -> Any:
    """Read a bounded JSON review document with duplicate-key protection."""

    if not 1 <= maximum_bytes <= MAXIMUM_REVIEW_BYTES:
        raise ValueError("maximum_bytes must stay within the review-document limit.")
    try:
        if not path.is_file():
            raise ReviewDocumentError("Review input must be a regular file.")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise ReviewDocumentError(
                f"Review input exceeds the {maximum_bytes}-byte validation limit."
            )
        raw = path.read_bytes()
        if len(raw) != size:
            raise ReviewDocumentError("Review input changed while it was being read.")
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except ReviewDocumentError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReviewDocumentError(f"Could not read bounded UTF-8 review JSON: {exc}") from exc
    _validate_json_shape(document)
    return document


@dataclass(frozen=True, slots=True)
class QualifiedFindingReview:
    review_id: str
    batch_id: str
    batch_digest: str
    finding_id: str
    finding_fingerprint: str
    assessment_type: AssessmentType
    disposition: ReviewDisposition
    reviewer_id: str
    reviewer_role: ReviewerRole
    qualification_evidence_ref: str
    reviewed_at: datetime
    rationale: str
    validation_evidence_refs: tuple[str, ...]
    final_severity: FinalSeverity | None
    severity_override_reason: str
    business_impact: str
    recommendation: str
    control_refs: tuple[str, ...]
    control_profile_id: str
    control_profile_digest: str
    duplicate_of: str
    human_review_asserted: bool = True

    def __post_init__(self) -> None:
        if not _REVIEW_ID.fullmatch(self.review_id):
            raise ValueError("review_id must use the derived FRX-REV identifier format.")
        if not _DIGEST.fullmatch(self.batch_digest) or not _DIGEST.fullmatch(
            self.finding_fingerprint
        ):
            raise ValueError("Review source digests must be lowercase SHA-256 values.")
        _require_text(self.batch_id, "batch_id", 80)
        _require_text(self.finding_id, "finding_id", 80)
        _require_text(self.reviewer_id, "reviewer_id", 160)
        _require_text(self.rationale, "rationale", MAXIMUM_TEXT, minimum=20)
        _require_reference(
            self.qualification_evidence_ref,
            "qualification_evidence_ref",
            prefixes=("qualification-evidence://",),
        )
        _require_references(self.validation_evidence_refs, "validation_evidence_refs")
        if self.reviewer_role != ReviewerRole.QUALIFIED_TESTER:
            raise ValueError("Finding dispositions require the qualified_tester role.")
        if self.human_review_asserted is not True:
            raise ValueError("A review must explicitly assert qualified human authorship.")
        object.__setattr__(self, "reviewed_at", ensure_aware(self.reviewed_at))
        object.__setattr__(
            self,
            "validation_evidence_refs",
            tuple(sorted(set(self.validation_evidence_refs))),
        )
        object.__setattr__(self, "control_refs", tuple(sorted(set(self.control_refs))))
        _validate_disposition_fields(self)
        _validate_control_profile(self)
        if self.review_id != _review_id(self.payload_digest()):
            raise ValueError("review_id does not match the immutable review payload.")

    def payload(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "batch_digest": self.batch_digest,
            "finding_id": self.finding_id,
            "finding_fingerprint": self.finding_fingerprint,
            "assessment_type": self.assessment_type,
            "disposition": self.disposition,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role,
            "qualification_evidence_ref": self.qualification_evidence_ref,
            "reviewed_at": self.reviewed_at,
            "rationale": self.rationale,
            "validation_evidence_refs": self.validation_evidence_refs,
            "final_severity": self.final_severity,
            "severity_override_reason": self.severity_override_reason,
            "business_impact": self.business_impact,
            "recommendation": self.recommendation,
            "control_refs": self.control_refs,
            "control_profile_id": self.control_profile_id,
            "control_profile_digest": self.control_profile_digest,
            "duplicate_of": self.duplicate_of,
            "human_review_asserted": self.human_review_asserted,
        }

    def payload_digest(self) -> str:
        return sha256_digest(self.payload())

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.finding-review.v1",
            **to_primitive(self),
            "review_digest": self.digest(),
            "cryptographic_signature_present": False,
        }


@dataclass(frozen=True, slots=True)
class RiskAcceptance:
    acceptance_id: str
    batch_id: str
    batch_digest: str
    finding_id: str
    finding_fingerprint: str
    review_id: str
    review_digest: str
    accepted_by: str
    acceptance_role: RiskAcceptanceRole
    approved_at: datetime
    expires_on: str
    approval_evidence_ref: str
    rationale: str
    compensating_controls: tuple[str, ...]
    human_approval_asserted: bool = True

    def __post_init__(self) -> None:
        if not _ACCEPTANCE_ID.fullmatch(self.acceptance_id):
            raise ValueError("acceptance_id must use the derived FRX-RISK identifier format.")
        for name in ("batch_digest", "finding_fingerprint", "review_digest"):
            if not _DIGEST.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest.")
        for name, value, limit in (
            ("batch_id", self.batch_id, 80),
            ("finding_id", self.finding_id, 80),
            ("review_id", self.review_id, 80),
            ("accepted_by", self.accepted_by, 160),
        ):
            _require_text(value, name, limit)
        if self.acceptance_role != RiskAcceptanceRole.BUSINESS_RISK_OWNER:
            raise ValueError("Risk acceptance requires the business_risk_owner role.")
        if self.human_approval_asserted is not True:
            raise ValueError("Risk acceptance must explicitly assert human approval.")
        approved_at = ensure_aware(self.approved_at)
        object.__setattr__(self, "approved_at", approved_at)
        try:
            expiry = date.fromisoformat(self.expires_on)
        except ValueError as exc:
            raise ValueError("expires_on must use YYYY-MM-DD format.") from exc
        days = (expiry - approved_at.date()).days
        if not 1 <= days <= 366:
            raise ValueError("Risk acceptance must expire within 1 to 366 days.")
        _require_reference(
            self.approval_evidence_ref,
            "approval_evidence_ref",
            prefixes=("attachment://", "evidence://"),
        )
        _require_text(self.rationale, "rationale", MAXIMUM_TEXT, minimum=20)
        if not self.compensating_controls:
            raise ValueError("Risk acceptance requires at least one compensating control.")
        for index, item in enumerate(self.compensating_controls):
            _require_text(item, f"compensating_controls[{index}]", 500, minimum=5)
        object.__setattr__(
            self,
            "compensating_controls",
            tuple(sorted(set(self.compensating_controls))),
        )
        if self.acceptance_id != _acceptance_id(self.payload_digest()):
            raise ValueError("acceptance_id does not match the immutable acceptance payload.")

    def payload(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "batch_digest": self.batch_digest,
            "finding_id": self.finding_id,
            "finding_fingerprint": self.finding_fingerprint,
            "review_id": self.review_id,
            "review_digest": self.review_digest,
            "accepted_by": self.accepted_by,
            "acceptance_role": self.acceptance_role,
            "approved_at": self.approved_at,
            "expires_on": self.expires_on,
            "approval_evidence_ref": self.approval_evidence_ref,
            "rationale": self.rationale,
            "compensating_controls": self.compensating_controls,
            "human_approval_asserted": self.human_approval_asserted,
        }

    def payload_digest(self) -> str:
        return sha256_digest(self.payload())

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.risk-acceptance.v1",
            **to_primitive(self),
            "acceptance_digest": self.digest(),
            "cryptographic_signature_present": False,
        }


@dataclass(frozen=True, slots=True)
class FindingReviewState:
    finding_id: str
    finding_fingerprint: str
    source_tool: str
    rule_id: str
    review_id: str
    review_digest: str
    outcome: ReviewOutcome
    final_severity: FinalSeverity | None
    duplicate_of: str
    risk_acceptance_id: str
    risk_acceptance_digest: str
    risk_acceptance_status: RiskAcceptanceStatus

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "finding_id", 80)
        if not _DIGEST.fullmatch(self.finding_fingerprint):
            raise ValueError("finding_fingerprint must be a lowercase SHA-256 digest.")
        _require_text(self.source_tool, "source_tool", 160)
        _require_text(self.rule_id, "rule_id", 200)

        pending = self.outcome == ReviewOutcome.PENDING_REVIEW
        if pending:
            if any(
                (
                    self.review_id,
                    self.review_digest,
                    self.duplicate_of,
                    self.risk_acceptance_id,
                    self.risk_acceptance_digest,
                )
            ):
                raise ValueError("Pending findings cannot carry review or acceptance records.")
            if self.final_severity is not None:
                raise ValueError("Pending findings cannot carry final severity.")
            if self.risk_acceptance_status != RiskAcceptanceStatus.NONE:
                raise ValueError("Pending findings cannot carry a risk-acceptance status.")
            return

        if not _REVIEW_ID.fullmatch(self.review_id) or not _DIGEST.fullmatch(
            self.review_digest
        ):
            raise ValueError("Reviewed findings require a valid review identity and digest.")
        if self.outcome in {ReviewOutcome.CONFIRMED, ReviewOutcome.ACCEPTED_RISK}:
            if self.final_severity is None:
                raise ValueError("Confirmed findings require final human severity.")
        elif self.final_severity is not None:
            raise ValueError("Non-confirmed findings cannot carry final severity.")
        if self.outcome == ReviewOutcome.DUPLICATE:
            _require_text(self.duplicate_of, "duplicate_of", 80)
        elif self.duplicate_of:
            raise ValueError("duplicate_of is valid only for a duplicate outcome.")

        acceptance_present = bool(
            self.risk_acceptance_id or self.risk_acceptance_digest
        )
        if self.risk_acceptance_status == RiskAcceptanceStatus.NONE:
            if acceptance_present:
                raise ValueError("Acceptance identifiers require an acceptance status.")
        else:
            if not _ACCEPTANCE_ID.fullmatch(self.risk_acceptance_id) or not _DIGEST.fullmatch(
                self.risk_acceptance_digest
            ):
                raise ValueError("Risk acceptance requires a valid identity and digest.")
            if self.risk_acceptance_status == RiskAcceptanceStatus.ACTIVE:
                if self.outcome != ReviewOutcome.ACCEPTED_RISK:
                    raise ValueError("Active risk acceptance requires accepted_risk outcome.")
            elif self.outcome != ReviewOutcome.CONFIRMED:
                raise ValueError("Expired risk acceptance returns the outcome to confirmed.")


@dataclass(frozen=True, slots=True)
class FindingReviewSummary:
    batch_id: str
    batch_digest: str
    assessment_type: AssessmentType
    as_of: datetime
    candidate_count: int
    reviewed_count: int
    pending_count: int
    confirmed_count: int
    false_positive_count: int
    duplicate_count: int
    not_applicable_count: int
    accepted_risk_count: int
    expired_risk_acceptance_count: int
    complete: bool
    states: tuple[FindingReviewState, ...]
    human_review_required: bool = True
    report_promotion_performed: bool = False

    def __post_init__(self) -> None:
        _require_text(self.batch_id, "batch_id", 80)
        if not _DIGEST.fullmatch(self.batch_digest):
            raise ValueError("batch_digest must be a lowercase SHA-256 digest.")
        if not isinstance(self.assessment_type, AssessmentType):
            raise ValueError("assessment_type must be a supported assessment type.")
        object.__setattr__(self, "as_of", ensure_aware(self.as_of))
        count_names = (
            "candidate_count",
            "reviewed_count",
            "pending_count",
            "confirmed_count",
            "false_positive_count",
            "duplicate_count",
            "not_applicable_count",
            "accepted_risk_count",
            "expired_risk_acceptance_count",
        )
        for name in count_names:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer.")
        if self.candidate_count != len(self.states):
            raise ValueError("candidate_count does not match review states.")
        if self.reviewed_count + self.pending_count != self.candidate_count:
            raise ValueError("Reviewed and pending counts do not cover the candidate set.")
        if self.complete != (self.pending_count == 0):
            raise ValueError("complete does not match the pending review count.")
        if self.human_review_required is not True or self.report_promotion_performed is not False:
            raise ValueError("Summary must preserve the human review and no-promotion boundary.")
        if len({item.finding_id for item in self.states}) != len(self.states):
            raise ValueError("Review summary finding states must be unique.")
        expected_counts = {
            "reviewed_count": sum(
                item.outcome != ReviewOutcome.PENDING_REVIEW for item in self.states
            ),
            "pending_count": sum(
                item.outcome == ReviewOutcome.PENDING_REVIEW for item in self.states
            ),
            "confirmed_count": sum(
                item.outcome == ReviewOutcome.CONFIRMED for item in self.states
            ),
            "false_positive_count": sum(
                item.outcome == ReviewOutcome.FALSE_POSITIVE for item in self.states
            ),
            "duplicate_count": sum(
                item.outcome == ReviewOutcome.DUPLICATE for item in self.states
            ),
            "not_applicable_count": sum(
                item.outcome == ReviewOutcome.NOT_APPLICABLE for item in self.states
            ),
            "accepted_risk_count": sum(
                item.outcome == ReviewOutcome.ACCEPTED_RISK for item in self.states
            ),
            "expired_risk_acceptance_count": sum(
                item.risk_acceptance_status == RiskAcceptanceStatus.EXPIRED
                for item in self.states
            ),
        }
        for name, expected in expected_counts.items():
            if getattr(self, name) != expected:
                raise ValueError(f"{name} does not match the finding states.")
        object.__setattr__(
            self,
            "states",
            tuple(sorted(self.states, key=lambda item: item.finding_id)),
        )

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.finding-review-summary.v1",
            **to_primitive(self),
            "summary_digest": self.digest(),
            "audit_support_only": True,
        }


def review_template_document(
    batch: EvidenceIntakeBatch,
    finding_id: str,
    assessment_type: AssessmentType,
) -> dict[str, Any]:
    if not isinstance(assessment_type, AssessmentType):
        raise ValueError("assessment_type must be a supported assessment type.")
    finding = _candidate(batch, finding_id)
    control_profile = turkey_financial_regulatory_profile()
    return {
        "schema_version": "finredops.finding-review-draft.v1",
        "batch_id": batch.batch_id,
        "batch_digest": batch.digest(),
        "finding_id": finding.finding_id,
        "finding_fingerprint": finding.fingerprint,
        "assessment_type": assessment_type.value,
        "disposition": "TODO",
        "reviewer_id": "TODO",
        "reviewer_role": ReviewerRole.QUALIFIED_TESTER.value,
        "qualification_evidence_ref": "qualification-evidence://TODO",
        "reviewed_at": "YYYY-MM-DDTHH:MM:SSZ",
        "rationale": "TODO: document the validation performed and the disposition rationale.",
        "validation_evidence_refs": [],
        "final_severity": None,
        "severity_override_reason": "",
        "business_impact": "",
        "recommendation": "",
        "control_refs": [],
        "control_profile_id": control_profile.profile_id,
        "control_profile_digest": control_profile.digest(),
        "duplicate_of": "",
        "human_review_asserted": True,
        "machine_context": {
            "source_tool": finding.source_tool,
            "rule_id": finding.rule_id,
            "machine_severity": finding.machine_severity.value,
            "machine_confidence": finding.machine_confidence.value,
            "artifact_ref": finding.artifact_ref,
        },
    }


def review_from_draft(
    document: Any, batch: EvidenceIntakeBatch
) -> QualifiedFindingReview:
    fields = _review_fields()
    metadata = {"schema_version", "machine_context"}
    _strict_fields(document, fields, metadata, "Finding review draft")
    if document.get("schema_version") != "finredops.finding-review-draft.v1":
        raise ReviewDocumentError("Unsupported finding review draft schema version.")
    _verify_machine_context(document.get("machine_context"), batch, document.get("finding_id"))
    return _build_review(document, batch)


def review_from_document(
    document: Any, batch: EvidenceIntakeBatch
) -> QualifiedFindingReview:
    fields = _review_fields() | {"review_id"}
    metadata = {"schema_version", "review_digest", "cryptographic_signature_present"}
    _strict_fields(document, fields, metadata, "Finding review")
    if document.get("schema_version") != "finredops.finding-review.v1":
        raise ReviewDocumentError("Unsupported finding review schema version.")
    if document.get("cryptographic_signature_present") is not False:
        raise ReviewDocumentError("This contract does not claim a cryptographic signature.")
    review = _build_review(document, batch, supplied_id=document.get("review_id"))
    if document.get("review_digest") != review.digest():
        raise ReviewDocumentError("Finding review digest does not match its content.")
    return review


def risk_acceptance_template_document(review: QualifiedFindingReview) -> dict[str, Any]:
    if review.disposition != ReviewDisposition.CONFIRMED:
        raise ValueError("Only a confirmed finding can receive a risk-acceptance draft.")
    return {
        "schema_version": "finredops.risk-acceptance-draft.v1",
        "batch_id": review.batch_id,
        "batch_digest": review.batch_digest,
        "finding_id": review.finding_id,
        "finding_fingerprint": review.finding_fingerprint,
        "review_id": review.review_id,
        "review_digest": review.digest(),
        "accepted_by": "TODO",
        "acceptance_role": RiskAcceptanceRole.BUSINESS_RISK_OWNER.value,
        "approved_at": "YYYY-MM-DDTHH:MM:SSZ",
        "expires_on": "YYYY-MM-DD",
        "approval_evidence_ref": "attachment://TODO/risk-acceptance",
        "rationale": "TODO: document the accountable business decision and residual risk.",
        "compensating_controls": [],
        "human_approval_asserted": True,
    }


def risk_acceptance_from_draft(
    document: Any,
    batch: EvidenceIntakeBatch,
    review: QualifiedFindingReview,
) -> RiskAcceptance:
    fields = _acceptance_fields()
    _strict_fields(document, fields, {"schema_version"}, "Risk acceptance draft")
    if document.get("schema_version") != "finredops.risk-acceptance-draft.v1":
        raise ReviewDocumentError("Unsupported risk-acceptance draft schema version.")
    return _build_acceptance(document, batch, review)


def risk_acceptance_from_document(
    document: Any,
    batch: EvidenceIntakeBatch,
    review: QualifiedFindingReview,
) -> RiskAcceptance:
    fields = _acceptance_fields() | {"acceptance_id"}
    metadata = {"schema_version", "acceptance_digest", "cryptographic_signature_present"}
    _strict_fields(document, fields, metadata, "Risk acceptance")
    if document.get("schema_version") != "finredops.risk-acceptance.v1":
        raise ReviewDocumentError("Unsupported risk-acceptance schema version.")
    if document.get("cryptographic_signature_present") is not False:
        raise ReviewDocumentError("This contract does not claim a cryptographic signature.")
    acceptance = _build_acceptance(
        document,
        batch,
        review,
        supplied_id=document.get("acceptance_id"),
    )
    if document.get("acceptance_digest") != acceptance.digest():
        raise ReviewDocumentError("Risk-acceptance digest does not match its content.")
    return acceptance


def review_summary_from_document(
    document: Any,
    batch: EvidenceIntakeBatch,
) -> FindingReviewSummary:
    """Load and verify a deterministic summary against its source intake."""

    fields = {
        "batch_id",
        "batch_digest",
        "assessment_type",
        "as_of",
        "candidate_count",
        "reviewed_count",
        "pending_count",
        "confirmed_count",
        "false_positive_count",
        "duplicate_count",
        "not_applicable_count",
        "accepted_risk_count",
        "expired_risk_acceptance_count",
        "complete",
        "states",
        "human_review_required",
        "report_promotion_performed",
    }
    metadata = {"schema_version", "summary_digest", "audit_support_only"}
    _strict_fields(document, fields, metadata, "Finding review summary")
    if document.get("schema_version") != "finredops.finding-review-summary.v1":
        raise ReviewDocumentError("Unsupported finding-review summary schema version.")
    if document.get("audit_support_only") is not True:
        raise ReviewDocumentError("A review summary must remain audit-support only.")
    raw_states = document.get("states")
    if not isinstance(raw_states, list) or len(raw_states) > MAXIMUM_REVIEWS:
        raise ReviewDocumentError("states must be a bounded array.")
    states = tuple(_review_state_from_document(item) for item in raw_states)
    summary = FindingReviewSummary(
        batch_id=_text(document, "batch_id", 80),
        batch_digest=_text(document, "batch_digest", 64),
        assessment_type=AssessmentType(_text(document, "assessment_type", 80)),
        as_of=parse_datetime(_text(document, "as_of", 50)),
        candidate_count=_strict_integer(document, "candidate_count"),
        reviewed_count=_strict_integer(document, "reviewed_count"),
        pending_count=_strict_integer(document, "pending_count"),
        confirmed_count=_strict_integer(document, "confirmed_count"),
        false_positive_count=_strict_integer(document, "false_positive_count"),
        duplicate_count=_strict_integer(document, "duplicate_count"),
        not_applicable_count=_strict_integer(document, "not_applicable_count"),
        accepted_risk_count=_strict_integer(document, "accepted_risk_count"),
        expired_risk_acceptance_count=_strict_integer(
            document, "expired_risk_acceptance_count"
        ),
        complete=_strict_bool(document, "complete"),
        states=states,
        human_review_required=_strict_bool(document, "human_review_required"),
        report_promotion_performed=_strict_bool(
            document, "report_promotion_performed"
        ),
    )
    if summary.batch_id != batch.batch_id or summary.batch_digest != batch.digest():
        raise ReviewDocumentError("Review summary is bound to another intake revision.")
    candidates = {item.finding_id: item for item in batch.findings}
    if set(candidates) != {item.finding_id for item in summary.states}:
        raise ReviewDocumentError("Review summary does not cover the exact candidate set.")
    for state in summary.states:
        candidate = candidates[state.finding_id]
        if (
            state.finding_fingerprint != candidate.fingerprint
            or state.source_tool != candidate.source_tool
            or state.rule_id != candidate.rule_id
        ):
            raise ReviewDocumentError(
                f"Review state {state.finding_id} does not match its intake candidate."
            )
    if document.get("summary_digest") != summary.digest():
        raise ReviewDocumentError("Finding-review summary digest does not match its content.")
    return summary


def build_review_summary(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptances: Sequence[RiskAcceptance] = (),
    *,
    assessment_type: AssessmentType,
    as_of: datetime,
) -> FindingReviewSummary:
    if len(reviews) > MAXIMUM_REVIEWS or len(acceptances) > MAXIMUM_REVIEWS:
        raise ValueError("Review summary exceeds the bounded record limit.")
    if not isinstance(assessment_type, AssessmentType):
        raise ValueError("assessment_type must be a supported assessment type.")
    as_of = ensure_aware(as_of)
    candidates = {item.finding_id: item for item in batch.findings}
    review_map: dict[str, QualifiedFindingReview] = {}
    for review in reviews:
        validate_review_binding(review, batch)
        if review.assessment_type != assessment_type:
            raise ValueError("All reviews must match the summary assessment type.")
        if review.reviewed_at > as_of:
            raise ValueError("Review summary as_of time precedes a supplied review.")
        if review.finding_id in review_map:
            raise ValueError(f"Finding {review.finding_id} has more than one active review.")
        review_map[review.finding_id] = review
    _validate_duplicate_graph(review_map, candidates)

    acceptance_map: dict[str, RiskAcceptance] = {}
    for acceptance in acceptances:
        review = review_map.get(acceptance.finding_id)
        if review is None:
            raise ValueError("Risk acceptance references a finding without an active review.")
        validate_risk_acceptance_binding(acceptance, batch, review)
        if acceptance.approved_at > as_of:
            raise ValueError("Review summary as_of time precedes a supplied acceptance.")
        if acceptance.finding_id in acceptance_map:
            raise ValueError(
                f"Finding {acceptance.finding_id} has more than one active risk acceptance."
            )
        acceptance_map[acceptance.finding_id] = acceptance

    states: list[FindingReviewState] = []
    for finding_id, finding in sorted(candidates.items()):
        review = review_map.get(finding_id)
        if review is None:
            states.append(_pending_state(finding))
            continue
        acceptance = acceptance_map.get(finding_id)
        status = RiskAcceptanceStatus.NONE
        acceptance_id = ""
        acceptance_digest = ""
        outcome = ReviewOutcome(review.disposition.value)
        if acceptance is not None:
            acceptance_id = acceptance.acceptance_id
            acceptance_digest = acceptance.digest()
            if date.fromisoformat(acceptance.expires_on) >= as_of.date():
                status = RiskAcceptanceStatus.ACTIVE
                outcome = ReviewOutcome.ACCEPTED_RISK
            else:
                status = RiskAcceptanceStatus.EXPIRED
                outcome = ReviewOutcome.CONFIRMED
        states.append(
            FindingReviewState(
                finding_id=finding.finding_id,
                finding_fingerprint=finding.fingerprint,
                source_tool=finding.source_tool,
                rule_id=finding.rule_id,
                review_id=review.review_id,
                review_digest=review.digest(),
                outcome=outcome,
                final_severity=review.final_severity,
                duplicate_of=review.duplicate_of,
                risk_acceptance_id=acceptance_id,
                risk_acceptance_digest=acceptance_digest,
                risk_acceptance_status=status,
            )
        )

    def count(outcome: ReviewOutcome) -> int:
        return sum(item.outcome == outcome for item in states)

    reviewed = len(review_map)
    pending = len(candidates) - reviewed
    return FindingReviewSummary(
        batch_id=batch.batch_id,
        batch_digest=batch.digest(),
        assessment_type=assessment_type,
        as_of=as_of,
        candidate_count=len(candidates),
        reviewed_count=reviewed,
        pending_count=pending,
        confirmed_count=count(ReviewOutcome.CONFIRMED),
        false_positive_count=count(ReviewOutcome.FALSE_POSITIVE),
        duplicate_count=count(ReviewOutcome.DUPLICATE),
        not_applicable_count=count(ReviewOutcome.NOT_APPLICABLE),
        accepted_risk_count=count(ReviewOutcome.ACCEPTED_RISK),
        expired_risk_acceptance_count=sum(
            item.risk_acceptance_status == RiskAcceptanceStatus.EXPIRED for item in states
        ),
        complete=pending == 0,
        states=tuple(states),
    )


def validate_review_binding(
    review: QualifiedFindingReview, batch: EvidenceIntakeBatch
) -> None:
    finding = _candidate(batch, review.finding_id)
    if review.batch_id != batch.batch_id or review.batch_digest != batch.digest():
        raise ValueError("Finding review is bound to another intake batch or revision.")
    if review.finding_fingerprint != finding.fingerprint:
        raise ValueError("Finding review fingerprint does not match the candidate.")
    expected_machine_severity = FinalSeverity(finding.machine_severity.value)
    if review.disposition == ReviewDisposition.CONFIRMED:
        changed = review.final_severity != expected_machine_severity
        if changed and len(review.severity_override_reason.strip()) < 20:
            raise ValueError("A machine-severity change requires a substantive rationale.")
        if not changed and review.severity_override_reason.strip():
            raise ValueError("severity_override_reason is only valid when severity changes.")
    if review.disposition == ReviewDisposition.DUPLICATE:
        target = _candidate(batch, review.duplicate_of)
        if target.finding_id == review.finding_id:
            raise ValueError("A finding cannot be a duplicate of itself.")


def validate_risk_acceptance_binding(
    acceptance: RiskAcceptance,
    batch: EvidenceIntakeBatch,
    review: QualifiedFindingReview,
) -> None:
    validate_review_binding(review, batch)
    if review.disposition != ReviewDisposition.CONFIRMED:
        raise ValueError("Only a confirmed finding can receive risk acceptance.")
    expected = (
        review.batch_id,
        review.batch_digest,
        review.finding_id,
        review.finding_fingerprint,
        review.review_id,
        review.digest(),
    )
    supplied = (
        acceptance.batch_id,
        acceptance.batch_digest,
        acceptance.finding_id,
        acceptance.finding_fingerprint,
        acceptance.review_id,
        acceptance.review_digest,
    )
    if supplied != expected:
        raise ValueError("Risk acceptance is not bound to the exact confirmed review.")
    if acceptance.accepted_by == review.reviewer_id:
        raise ValueError("The qualified tester cannot accept the business risk they reviewed.")
    if acceptance.approved_at < review.reviewed_at:
        raise ValueError("Risk acceptance cannot precede the qualified finding review.")


def _build_review(
    document: Mapping[str, Any],
    batch: EvidenceIntakeBatch,
    *,
    supplied_id: Any = None,
) -> QualifiedFindingReview:
    _reject_sensitive_content(
        document,
        (
            "reviewer_id",
            "qualification_evidence_ref",
            "rationale",
            "validation_evidence_refs",
            "severity_override_reason",
            "business_impact",
            "recommendation",
        ),
    )
    _reject_template_placeholders(
        document,
        ("reviewer_id", "qualification_evidence_ref", "rationale"),
    )
    finding = _candidate(batch, _text(document, "finding_id", 80))
    values = {
        "batch_id": _text(document, "batch_id", 80),
        "batch_digest": _text(document, "batch_digest", 64),
        "finding_id": finding.finding_id,
        "finding_fingerprint": _text(document, "finding_fingerprint", 64),
        "assessment_type": AssessmentType(_text(document, "assessment_type", 80)),
        "disposition": ReviewDisposition(_text(document, "disposition", 40)),
        "reviewer_id": _text(document, "reviewer_id", 160),
        "reviewer_role": ReviewerRole(_text(document, "reviewer_role", 40)),
        "qualification_evidence_ref": _text(
            document, "qualification_evidence_ref", 500
        ),
        "reviewed_at": parse_datetime(_text(document, "reviewed_at", 50)),
        "rationale": _text(document, "rationale", MAXIMUM_TEXT),
        "validation_evidence_refs": tuple(
            sorted(
                _strings(document, "validation_evidence_refs", allow_empty=False)
            )
        ),
        "final_severity": _optional_severity(document.get("final_severity")),
        "severity_override_reason": _text(
            document, "severity_override_reason", MAXIMUM_TEXT, allow_empty=True
        ),
        "business_impact": _text(
            document, "business_impact", MAXIMUM_TEXT, allow_empty=True
        ),
        "recommendation": _text(
            document, "recommendation", MAXIMUM_TEXT, allow_empty=True
        ),
        "control_refs": tuple(sorted(_strings(document, "control_refs"))),
        "control_profile_id": _text(document, "control_profile_id", 160),
        "control_profile_digest": _text(
            document, "control_profile_digest", 64
        ),
        "duplicate_of": _text(document, "duplicate_of", 80, allow_empty=True),
        "human_review_asserted": _strict_bool(document, "human_review_asserted"),
    }
    payload_digest = sha256_digest(values)
    review = QualifiedFindingReview(
        review_id=_review_id(payload_digest) if supplied_id is None else str(supplied_id),
        **values,
    )
    validate_review_binding(review, batch)
    return review


def _build_acceptance(
    document: Mapping[str, Any],
    batch: EvidenceIntakeBatch,
    review: QualifiedFindingReview,
    *,
    supplied_id: Any = None,
) -> RiskAcceptance:
    _reject_sensitive_content(
        document,
        (
            "accepted_by",
            "approval_evidence_ref",
            "rationale",
            "compensating_controls",
        ),
    )
    _reject_template_placeholders(
        document,
        ("accepted_by", "approval_evidence_ref", "rationale"),
    )
    values = {
        "batch_id": _text(document, "batch_id", 80),
        "batch_digest": _text(document, "batch_digest", 64),
        "finding_id": _text(document, "finding_id", 80),
        "finding_fingerprint": _text(document, "finding_fingerprint", 64),
        "review_id": _text(document, "review_id", 80),
        "review_digest": _text(document, "review_digest", 64),
        "accepted_by": _text(document, "accepted_by", 160),
        "acceptance_role": RiskAcceptanceRole(
            _text(document, "acceptance_role", 40)
        ),
        "approved_at": parse_datetime(_text(document, "approved_at", 50)),
        "expires_on": _text(document, "expires_on", 10),
        "approval_evidence_ref": _text(document, "approval_evidence_ref", 500),
        "rationale": _text(document, "rationale", MAXIMUM_TEXT),
        "compensating_controls": tuple(
            sorted(_strings(document, "compensating_controls", allow_empty=False))
        ),
        "human_approval_asserted": _strict_bool(document, "human_approval_asserted"),
    }
    payload_digest = sha256_digest(values)
    acceptance = RiskAcceptance(
        acceptance_id=(
            _acceptance_id(payload_digest) if supplied_id is None else str(supplied_id)
        ),
        **values,
    )
    validate_risk_acceptance_binding(acceptance, batch, review)
    return acceptance


def _review_state_from_document(document: Any) -> FindingReviewState:
    fields = {
        "finding_id",
        "finding_fingerprint",
        "source_tool",
        "rule_id",
        "review_id",
        "review_digest",
        "outcome",
        "final_severity",
        "duplicate_of",
        "risk_acceptance_id",
        "risk_acceptance_digest",
        "risk_acceptance_status",
    }
    _strict_fields(document, fields, set(), "Finding review state")
    try:
        return FindingReviewState(
            finding_id=_text(document, "finding_id", 80),
            finding_fingerprint=_text(document, "finding_fingerprint", 64),
            source_tool=_text(document, "source_tool", 160),
            rule_id=_text(document, "rule_id", 200),
            review_id=_text(document, "review_id", 80, allow_empty=True),
            review_digest=_text(document, "review_digest", 64, allow_empty=True),
            outcome=ReviewOutcome(_text(document, "outcome", 40)),
            final_severity=_optional_severity(document.get("final_severity")),
            duplicate_of=_text(document, "duplicate_of", 80, allow_empty=True),
            risk_acceptance_id=_text(
                document, "risk_acceptance_id", 80, allow_empty=True
            ),
            risk_acceptance_digest=_text(
                document, "risk_acceptance_digest", 64, allow_empty=True
            ),
            risk_acceptance_status=RiskAcceptanceStatus(
                _text(document, "risk_acceptance_status", 40)
            ),
        )
    except ValueError as exc:
        if isinstance(exc, ReviewDocumentError):
            raise
        raise ReviewDocumentError(f"Invalid finding review state: {exc}") from exc


def _validate_disposition_fields(review: QualifiedFindingReview) -> None:
    confirmed = review.disposition == ReviewDisposition.CONFIRMED
    if confirmed:
        if review.final_severity is None:
            raise ValueError("Confirmed findings require a final human severity.")
        for name in ("business_impact", "recommendation"):
            _require_text(getattr(review, name), name, MAXIMUM_TEXT, minimum=20)
        if not review.control_refs:
            raise ValueError("Confirmed findings require at least one control reference.")
        for index, item in enumerate(review.control_refs):
            _require_text(item, f"control_refs[{index}]", 200)
    else:
        if review.final_severity is not None:
            raise ValueError("Non-confirmed dispositions cannot assign final severity.")
        if any(
            value.strip()
            for value in (
                review.severity_override_reason,
                review.business_impact,
                review.recommendation,
            )
        ) or review.control_refs:
            raise ValueError("Non-confirmed dispositions cannot carry report conclusions.")
    if review.disposition == ReviewDisposition.DUPLICATE:
        _require_text(review.duplicate_of, "duplicate_of", 80)
    elif review.duplicate_of:
        raise ValueError("duplicate_of is only valid for the duplicate disposition.")


def _validate_control_profile(review: QualifiedFindingReview) -> None:
    profile = turkey_financial_regulatory_profile()
    if (
        review.control_profile_id != profile.profile_id
        or review.control_profile_digest != profile.digest()
    ):
        raise ValueError("Finding review is not bound to the current control profile.")
    unknown = []
    inapplicable = []
    for control_id in review.control_refs:
        control = profile.get(control_id)
        if control is None:
            unknown.append(control_id)
        elif review.assessment_type not in control.assessment_types:
            inapplicable.append(control_id)
    if unknown:
        raise ValueError(
            f"Finding review contains unknown control references: {sorted(unknown)}."
        )
    if inapplicable:
        raise ValueError(
            "Finding review contains controls outside its assessment type: "
            f"{sorted(inapplicable)}."
        )


def _validate_duplicate_graph(
    reviews: Mapping[str, QualifiedFindingReview],
    candidates: Mapping[str, CanonicalFinding],
) -> None:
    for finding_id, review in reviews.items():
        if review.disposition != ReviewDisposition.DUPLICATE:
            continue
        if review.duplicate_of not in candidates:
            raise ValueError(
                f"Duplicate target {review.duplicate_of!r} is not in the intake batch."
            )
        target_review = reviews.get(review.duplicate_of)
        if target_review is None:
            raise ValueError("A duplicate target must have its own completed review.")
        if target_review.disposition != ReviewDisposition.CONFIRMED:
            raise ValueError(
                "A duplicate must point directly to a confirmed primary finding."
            )
        if finding_id == review.duplicate_of:
            raise ValueError("A finding cannot be a duplicate of itself.")


def _verify_machine_context(
    context: Any,
    batch: EvidenceIntakeBatch,
    finding_id: Any,
) -> None:
    if not isinstance(context, Mapping):
        raise ReviewDocumentError("machine_context must remain an object.")
    finding = _candidate(batch, str(finding_id))
    expected = {
        "source_tool": finding.source_tool,
        "rule_id": finding.rule_id,
        "machine_severity": finding.machine_severity.value,
        "machine_confidence": finding.machine_confidence.value,
        "artifact_ref": finding.artifact_ref,
    }
    if dict(context) != expected:
        raise ReviewDocumentError("machine_context does not match the immutable candidate.")


def _pending_state(finding: CanonicalFinding) -> FindingReviewState:
    return FindingReviewState(
        finding_id=finding.finding_id,
        finding_fingerprint=finding.fingerprint,
        source_tool=finding.source_tool,
        rule_id=finding.rule_id,
        review_id="",
        review_digest="",
        outcome=ReviewOutcome.PENDING_REVIEW,
        final_severity=None,
        duplicate_of="",
        risk_acceptance_id="",
        risk_acceptance_digest="",
        risk_acceptance_status=RiskAcceptanceStatus.NONE,
    )


def _candidate(batch: EvidenceIntakeBatch, finding_id: str) -> CanonicalFinding:
    matches = [item for item in batch.findings if item.finding_id == finding_id]
    if len(matches) != 1:
        raise ReviewDocumentError(f"Unknown finding candidate: {finding_id!r}.")
    return matches[0]


def _review_fields() -> set[str]:
    return {
        "batch_id",
        "batch_digest",
        "finding_id",
        "finding_fingerprint",
        "assessment_type",
        "disposition",
        "reviewer_id",
        "reviewer_role",
        "qualification_evidence_ref",
        "reviewed_at",
        "rationale",
        "validation_evidence_refs",
        "final_severity",
        "severity_override_reason",
        "business_impact",
        "recommendation",
        "control_refs",
        "control_profile_id",
        "control_profile_digest",
        "duplicate_of",
        "human_review_asserted",
    }


def _acceptance_fields() -> set[str]:
    return {
        "batch_id",
        "batch_digest",
        "finding_id",
        "finding_fingerprint",
        "review_id",
        "review_digest",
        "accepted_by",
        "acceptance_role",
        "approved_at",
        "expires_on",
        "approval_evidence_ref",
        "rationale",
        "compensating_controls",
        "human_approval_asserted",
    }


def _strict_fields(
    document: Any,
    fields: set[str],
    metadata: set[str],
    label: str,
) -> None:
    if not isinstance(document, Mapping):
        raise ReviewDocumentError(f"{label} must be a JSON object.")
    missing = fields - set(document)
    unknown = set(document) - fields - metadata
    if missing or unknown:
        raise ReviewDocumentError(
            f"Invalid {label.lower()} fields: missing {sorted(missing)}, "
            f"unknown {sorted(unknown)}."
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewDocumentError(f"Review JSON contains duplicate key {key!r}.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ReviewDocumentError(f"Review JSON contains a non-finite number: {value}.")


def _validate_json_shape(document: Any) -> None:
    stack: list[tuple[Any, int]] = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAXIMUM_REVIEW_NODES:
            raise ReviewDocumentError("Review JSON exceeds the structure limit.")
        if depth > MAXIMUM_REVIEW_DEPTH:
            raise ReviewDocumentError("Review JSON exceeds the nesting limit.")
        if isinstance(value, Mapping):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif value is None or isinstance(value, (str, bool, int)):
            continue
        elif isinstance(value, float) and math.isfinite(value):
            continue
        else:
            raise ReviewDocumentError("Review JSON contains an unsupported value.")


def _text(
    document: Mapping[str, Any],
    name: str,
    maximum: int,
    *,
    allow_empty: bool = False,
) -> str:
    value = document.get(name)
    if not isinstance(value, str):
        raise ReviewDocumentError(f"{name} must be a string.")
    normalized = value.strip()
    if (not allow_empty and not normalized) or len(normalized) > maximum or _CONTROL.search(
        normalized
    ):
        raise ReviewDocumentError(f"{name} violates its safe text boundary.")
    return normalized


def _strings(
    document: Mapping[str, Any],
    name: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    value = document.get(name)
    if not isinstance(value, list) or len(value) > MAXIMUM_REFERENCES:
        raise ReviewDocumentError(f"{name} must be a bounded string array.")
    if not value and not allow_empty:
        raise ReviewDocumentError(f"{name} cannot be empty.")
    parsed = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ReviewDocumentError(f"{name}[{index}] must be a string.")
        normalized = item.strip()
        if not normalized or len(normalized) > 500 or _CONTROL.search(normalized):
            raise ReviewDocumentError(f"{name}[{index}] violates its text boundary.")
        parsed.append(normalized)
    if len(parsed) != len(set(parsed)):
        raise ReviewDocumentError(f"{name} cannot contain duplicates.")
    return tuple(parsed)


def _strict_bool(document: Mapping[str, Any], name: str) -> bool:
    value = document.get(name)
    if not isinstance(value, bool):
        raise ReviewDocumentError(f"{name} must be a JSON boolean.")
    return value


def _strict_integer(document: Mapping[str, Any], name: str) -> int:
    value = document.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReviewDocumentError(f"{name} must be a non-negative integer.")
    return value


def _reject_sensitive_content(
    document: Mapping[str, Any], names: tuple[str, ...]
) -> None:
    candidate = {name: document.get(name) for name in names}
    if EvidenceGuard().sanitize(candidate).redacted:
        raise ReviewDocumentError(
            "Review text contains a likely secret or regulated identifier; "
            "store it in the evidence vault and use an opaque reference."
        )


def _reject_template_placeholders(
    document: Mapping[str, Any], names: tuple[str, ...]
) -> None:
    for name in names:
        value = document.get(name)
        if not isinstance(value, str):
            continue
        normalized = value.strip().casefold()
        if normalized == "todo" or normalized.startswith("todo:") or "://todo" in normalized:
            raise ReviewDocumentError(f"{name} still contains a template placeholder.")


def _optional_severity(value: Any) -> FinalSeverity | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReviewDocumentError("final_severity must be null or a severity string.")
    try:
        return FinalSeverity(value)
    except ValueError as exc:
        raise ReviewDocumentError("final_severity is not supported.") from exc


def _require_text(
    value: str,
    name: str,
    maximum: int,
    *,
    minimum: int = 1,
) -> None:
    if (
        not isinstance(value, str)
        or len(value.strip()) < minimum
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise ValueError(f"{name} violates its safe text boundary.")


def _require_reference(
    value: str,
    name: str,
    *,
    prefixes: tuple[str, ...] = _EVIDENCE_PREFIXES,
) -> None:
    _require_text(value, name, 500)
    if not value.startswith(prefixes):
        raise ValueError(f"{name} must use an approved opaque evidence URI.")


def _require_references(values: tuple[str, ...], name: str) -> None:
    if not values or len(values) > MAXIMUM_REFERENCES:
        raise ValueError(f"{name} must contain bounded review evidence.")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} cannot contain duplicates.")
    for index, item in enumerate(values):
        _require_reference(item, f"{name}[{index}]")


def _review_id(payload_digest: str) -> str:
    return f"FRX-REV-{payload_digest[:24].upper()}"


def _acceptance_id(payload_digest: str) -> str:
    return f"FRX-RISK-{payload_digest[:24].upper()}"
