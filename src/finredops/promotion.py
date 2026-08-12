"""Explicit, fail-closed promotion of qualified reviews into draft reports.

This module is the only bridge between machine-finding review records and the
reporting model. It requires a complete qualified-review set, preserves exact
intake/review digests, requires human-supplied affected-asset and ownership
metadata, and can only create ``draft`` assessment reports. It never executes a
scanner, contacts a target, infers control conformance from missing findings, or
issues a report.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .intake import EvidenceIntakeBatch, import_sarif_file, read_intake_file
from .models import parse_datetime, sha256_digest
from .regulations import AssessmentType, turkey_financial_regulatory_profile
from .reporting import (
    REQUIRED_COVERAGE,
    AssessmentReport,
    ControlAssessment,
    ControlConclusion,
    FindingSeverity,
    FindingStatus,
    ReportStatus,
    RetestStatus,
    SecurityFinding,
    render_report_markdown,
    validate_report,
)
from .review import (
    QualifiedFindingReview,
    ReviewDisposition,
    ReviewOutcome,
    RiskAcceptance,
    build_review_summary,
    read_review_json,
    review_from_document,
    review_from_draft,
    review_template_document,
    risk_acceptance_from_document,
)


class ReportPromotionError(ValueError):
    """Raised when reviewed findings cannot be safely assembled into a report."""


_SPEC_FIELDS = {
    "schema_version",
    "report_id",
    "title",
    "assessment_type",
    "organization",
    "period_start",
    "period_end",
    "issued_at",
    "classification",
    "rules_of_engagement_ref",
    "in_scope_assets",
    "excluded_assets",
    "tester_organization",
    "lead_tester",
    "independence_declaration",
    "tester_qualifications",
    "methodology",
    "executive_summary",
    "limitations",
    "finding_metadata",
}


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ReportPromotionError(f"{name} must be a non-empty string.")
    return value.strip()


def _strings(value: Any, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ReportPromotionError(f"{name} must be a string array.")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ReportPromotionError(f"{name} must contain only non-empty strings.")
    return tuple(item.strip() for item in value)


def _reviewed_report_spec(document: Any) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ReportPromotionError("Reviewed-report specification must be a JSON object.")
    if set(document) != _SPEC_FIELDS:
        missing = sorted(_SPEC_FIELDS - set(document))
        unknown = sorted(set(document) - _SPEC_FIELDS)
        raise ReportPromotionError(
            f"Invalid reviewed-report spec fields: missing {missing}, unknown {unknown}."
        )
    if document.get("schema_version") != "finredops.reviewed-report-spec.v1":
        raise ReportPromotionError("Unsupported reviewed-report spec schema version.")
    finding_metadata = document.get("finding_metadata")
    if not isinstance(finding_metadata, Mapping):
        raise ReportPromotionError("finding_metadata must be an object keyed by finding_id.")
    normalized_metadata: dict[str, dict[str, Any]] = {}
    for finding_id, raw in finding_metadata.items():
        if not isinstance(finding_id, str) or not finding_id.strip() or not isinstance(raw, Mapping):
            raise ReportPromotionError("finding_metadata contains an invalid entry.")
        required = {"affected_assets", "owner", "due_date"}
        if set(raw) != required:
            raise ReportPromotionError(
                f"finding_metadata[{finding_id!r}] must contain exactly {sorted(required)}."
            )
        normalized_metadata[finding_id] = {
            "affected_assets": _strings(
                raw.get("affected_assets"),
                f"finding_metadata[{finding_id}].affected_assets",
                allow_empty=False,
            ),
            "owner": _string(raw.get("owner"), f"finding_metadata[{finding_id}].owner"),
            "due_date": _string(
                raw.get("due_date"), f"finding_metadata[{finding_id}].due_date"
            ),
        }
    return {
        "report_id": _string(document.get("report_id"), "report_id"),
        "title": _string(document.get("title"), "title"),
        "assessment_type": AssessmentType(
            _string(document.get("assessment_type"), "assessment_type")
        ),
        "organization": _string(document.get("organization"), "organization"),
        "period_start": _string(document.get("period_start"), "period_start"),
        "period_end": _string(document.get("period_end"), "period_end"),
        "issued_at": parse_datetime(_string(document.get("issued_at"), "issued_at")),
        "classification": _string(document.get("classification"), "classification"),
        "rules_of_engagement_ref": _string(
            document.get("rules_of_engagement_ref"), "rules_of_engagement_ref"
        ),
        "in_scope_assets": _strings(
            document.get("in_scope_assets"), "in_scope_assets", allow_empty=False
        ),
        "excluded_assets": _strings(document.get("excluded_assets"), "excluded_assets"),
        "tester_organization": _string(
            document.get("tester_organization"), "tester_organization"
        ),
        "lead_tester": _string(document.get("lead_tester"), "lead_tester"),
        "independence_declaration": _string(
            document.get("independence_declaration"),
            "independence_declaration",
            allow_empty=True,
        ),
        "tester_qualifications": _strings(
            document.get("tester_qualifications"), "tester_qualifications"
        ),
        "methodology": _strings(
            document.get("methodology"), "methodology", allow_empty=False
        ),
        "executive_summary": _string(
            document.get("executive_summary"), "executive_summary"
        ),
        "limitations": _strings(document.get("limitations"), "limitations"),
        "finding_metadata": normalized_metadata,
    }


def build_reviewed_report(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptances: Sequence[RiskAcceptance],
    spec_document: Any,
    *,
    as_of: datetime | None = None,
) -> tuple[AssessmentReport, dict[str, Any]]:
    """Promote only completed, human-confirmed reviews into a draft report.

    A complete disposition set is mandatory so a caller cannot silently omit a
    pending candidate. False positives, duplicates, and not-applicable records
    remain represented by the review summary but are not report findings.
    """

    spec = _reviewed_report_spec(spec_document)
    assessment_type = spec["assessment_type"]
    effective_as_of = as_of or spec["issued_at"]
    summary = build_review_summary(
        batch,
        reviews,
        acceptances,
        assessment_type=assessment_type,
        as_of=effective_as_of,
    )
    if not summary.complete:
        raise ReportPromotionError(
            "Report promotion requires a completed disposition for every intake candidate."
        )

    candidate_map = {item.finding_id: item for item in batch.findings}
    review_map = {item.finding_id: item for item in reviews}
    state_map = {item.finding_id: item for item in summary.states}
    promotable_ids = {
        item.finding_id
        for item in summary.states
        if item.outcome in {ReviewOutcome.CONFIRMED, ReviewOutcome.ACCEPTED_RISK}
    }
    supplied_metadata = set(spec["finding_metadata"])
    if supplied_metadata != promotable_ids:
        missing = sorted(promotable_ids - supplied_metadata)
        extra = sorted(supplied_metadata - promotable_ids)
        raise ReportPromotionError(
            "finding_metadata must cover exactly the promoted findings; "
            f"missing {missing}, extra {extra}."
        )

    findings: list[SecurityFinding] = []
    for finding_id in sorted(promotable_ids):
        candidate = candidate_map[finding_id]
        review = review_map[finding_id]
        state = state_map[finding_id]
        if review.disposition != ReviewDisposition.CONFIRMED or review.final_severity is None:
            raise ReportPromotionError(
                f"Promoted finding {finding_id} lacks a confirmed qualified review."
            )
        metadata = spec["finding_metadata"][finding_id]
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=candidate.title,
                severity=FindingSeverity(review.final_severity.value),
                affected_assets=metadata["affected_assets"],
                summary=review.rationale,
                business_impact=review.business_impact,
                recommendation=review.recommendation,
                evidence_refs=tuple(
                    sorted(
                        {
                            candidate.evidence_ref,
                            *review.validation_evidence_refs,
                        }
                    )
                ),
                control_refs=review.control_refs,
                owner=metadata["owner"],
                due_date=metadata["due_date"],
                status=(
                    FindingStatus.RISK_ACCEPTED
                    if state.outcome == ReviewOutcome.ACCEPTED_RISK
                    else FindingStatus.OPEN
                ),
                retest_status=RetestStatus.NOT_TESTED,
            )
        )

    profile = turkey_financial_regulatory_profile()
    summary_evidence = f"evidence://review-summary/{summary.digest()}"
    control_assessments: list[ControlAssessment] = []
    for control in profile.controls_for(assessment_type):
        linked = [item for item in findings if control.control_id in item.control_refs]
        if linked:
            evidence_refs = tuple(
                sorted({ref for item in linked for ref in item.evidence_refs})
            )
            control_assessments.append(
                ControlAssessment(
                    control_id=control.control_id,
                    conclusion=ControlConclusion.PARTIAL,
                    evidence_refs=evidence_refs,
                    finding_ids=tuple(sorted(item.finding_id for item in linked)),
                    notes=(
                        "Qualified, human-confirmed findings map to this control. "
                        "No conformance conclusion is inferred until remediation and retest."
                    ),
                )
            )
        else:
            control_assessments.append(
                ControlAssessment(
                    control_id=control.control_id,
                    conclusion=ControlConclusion.NOT_TESTED,
                    evidence_refs=(summary_evidence,),
                    finding_ids=(),
                    notes=(
                        "No promoted confirmed finding maps to this control. Absence of a "
                        "finding is not treated as evidence of conformance."
                    ),
                )
            )

    limitations = tuple(spec["limitations"]) + (
        "This draft was assembled only from a complete qualified-review set; machine candidates were not promoted without human disposition.",
        "Promotion does not issue the report, establish regulatory compliance, or replace independent human approval.",
    )
    report = AssessmentReport(
        report_id=spec["report_id"],
        title=spec["title"],
        assessment_type=assessment_type,
        organization=spec["organization"],
        period_start=spec["period_start"],
        period_end=spec["period_end"],
        issued_at=spec["issued_at"],
        classification=spec["classification"],
        rules_of_engagement_ref=spec["rules_of_engagement_ref"],
        in_scope_assets=spec["in_scope_assets"],
        excluded_assets=spec["excluded_assets"],
        tester_organization=spec["tester_organization"],
        lead_tester=spec["lead_tester"],
        independence_declaration=spec["independence_declaration"],
        tester_qualifications=spec["tester_qualifications"],
        methodology=spec["methodology"],
        coverage_areas=tuple(sorted(REQUIRED_COVERAGE[assessment_type])),
        executive_summary=(
            f"{spec['executive_summary']} Qualified review completed for "
            f"{summary.reviewed_count}/{summary.candidate_count} candidates; "
            f"{len(findings)} confirmed finding(s) were promoted into this draft."
        ),
        limitations=limitations,
        findings=tuple(findings),
        control_assessments=tuple(control_assessments),
        regulatory_profile_id=profile.profile_id,
        regulatory_profile_digest=profile.digest(),
        status=ReportStatus.DRAFT,
        human_approvals=(),
    )
    validation = validate_report(report, profile)
    if not validation.valid:
        errors = "; ".join(
            f"{item.code}:{item.path}" for item in validation.issues if item.blocking
        )
        raise ReportPromotionError(f"Promoted draft report is structurally invalid: {errors}")

    manifest_body = {
        "schema_version": "finredops.report-promotion.v1",
        "batch_id": batch.batch_id,
        "batch_digest": batch.digest(),
        "review_summary_digest": summary.digest(),
        "assessment_type": assessment_type.value,
        "candidate_count": summary.candidate_count,
        "reviewed_count": summary.reviewed_count,
        "confirmed_count": summary.confirmed_count,
        "accepted_risk_count": summary.accepted_risk_count,
        "omitted_nonconfirmed_count": (
            summary.false_positive_count
            + summary.duplicate_count
            + summary.not_applicable_count
        ),
        "promoted_finding_ids": sorted(promotable_ids),
        "report_id": report.report_id,
        "report_digest": report.digest(),
        "report_status": report.status.value,
        "human_approval_required": True,
        "automatic_conformance_inference": False,
        "report_issued": False,
        "audit_support_only": True,
    }
    manifest = {**manifest_body, "promotion_digest": sha256_digest(manifest_body)}
    return report, manifest


def _load_reviews(
    batch: EvidenceIntakeBatch, review_paths: Sequence[Path]
) -> tuple[QualifiedFindingReview, ...]:
    return tuple(
        review_from_document(read_review_json(path), batch) for path in review_paths
    )


def _load_acceptances(
    batch: EvidenceIntakeBatch,
    reviews: Sequence[QualifiedFindingReview],
    acceptance_paths: Sequence[Path],
) -> tuple[RiskAcceptance, ...]:
    by_finding = {item.finding_id: item for item in reviews}
    loaded: list[RiskAcceptance] = []
    for path in acceptance_paths:
        document = read_review_json(path)
        if not isinstance(document, Mapping):
            raise ReportPromotionError("Risk-acceptance document must be an object.")
        finding_id = document.get("finding_id")
        review = by_finding.get(str(finding_id))
        if review is None:
            raise ReportPromotionError(
                f"Risk acceptance {path} has no supplied matching review."
            )
        loaded.append(risk_acceptance_from_document(document, batch, review))
    return tuple(loaded)


def _write_outputs(
    output_dir: Path,
    report: AssessmentReport,
    manifest: Mapping[str, Any],
    reviews: Sequence[QualifiedFindingReview] = (),
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "regulatory-report.json").write_text(
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "regulatory-report.md").write_text(
        render_report_markdown(report), encoding="utf-8"
    )
    (output_dir / "promotion-manifest.json").write_text(
        json.dumps(dict(manifest), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if reviews:
        review_dir = output_dir / "reviews"
        review_dir.mkdir(parents=True, exist_ok=True)
        for review in reviews:
            (review_dir / f"{review.finding_id}.json").write_text(
                json.dumps(review.as_dict(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )


def build_from_files(
    *,
    intake_path: Path,
    review_paths: Sequence[Path],
    acceptance_paths: Sequence[Path],
    spec_path: Path,
    output_dir: Path,
) -> tuple[AssessmentReport, dict[str, Any]]:
    batch = read_intake_file(intake_path)
    reviews = _load_reviews(batch, review_paths)
    acceptances = _load_acceptances(batch, reviews, acceptance_paths)
    spec_document = read_review_json(spec_path)
    report, manifest = build_reviewed_report(batch, reviews, acceptances, spec_document)
    _write_outputs(output_dir, report, manifest)
    return report, manifest


def build_synthetic_demo(
    sarif_path: Path, output_dir: Path
) -> tuple[AssessmentReport, dict[str, Any]]:
    """Build a deterministic synthetic SARIF -> review -> draft-report example."""

    batch = import_sarif_file(sarif_path)
    if len(batch.findings) < 2:
        raise ReportPromotionError("Synthetic promotion demo requires at least two candidates.")
    assessment_type = AssessmentType.VENDOR_SOURCE_CODE_REVIEW
    confirmed_candidate = batch.findings[0]
    confirmed = review_template_document(
        batch, confirmed_candidate.finding_id, assessment_type
    )
    confirmed.update(
        {
            "disposition": "confirmed",
            "reviewer_id": "synthetic:qualified-tester",
            "qualification_evidence_ref": "qualification-evidence://synthetic/qualified-tester",
            "reviewed_at": "2026-08-12T12:10:00Z",
            "rationale": (
                "The synthetic qualified tester correlated the normalized scanner "
                "candidate with retained demonstration evidence and confirmed the condition."
            ),
            "validation_evidence_refs": [
                f"evidence://synthetic-review/{confirmed_candidate.fingerprint}"
            ],
            "final_severity": confirmed_candidate.machine_severity.value,
            "business_impact": (
                "In an equivalent authorized deployment, the confirmed condition could "
                "weaken application security controls and increase remediation risk."
            ),
            "recommendation": (
                "Correct the defensive implementation, retain change evidence, and perform "
                "an independent authorized retest before closure."
            ),
            "control_refs": ["TR-BDDK-BSEBY-22-4-5"],
        }
    )
    confirmed_review = review_from_draft(confirmed, batch)

    nonconfirmed_candidate = batch.findings[1]
    false_positive = review_template_document(
        batch, nonconfirmed_candidate.finding_id, assessment_type
    )
    false_positive.update(
        {
            "disposition": "false_positive",
            "reviewer_id": "synthetic:qualified-tester",
            "qualification_evidence_ref": "qualification-evidence://synthetic/qualified-tester",
            "reviewed_at": "2026-08-12T12:11:00Z",
            "rationale": (
                "The synthetic qualified tester reviewed the retained evidence and determined "
                "that the second normalized candidate does not represent a reportable condition."
            ),
            "validation_evidence_refs": [
                f"evidence://synthetic-review/{nonconfirmed_candidate.fingerprint}"
            ],
        }
    )
    false_positive_review = review_from_draft(false_positive, batch)
    reviews = (confirmed_review, false_positive_review)

    spec = {
        "schema_version": "finredops.reviewed-report-spec.v1",
        "report_id": "FRX-RPT-REVIEWED-DEMO-001",
        "title": "Sentetik Qualified-Review Kaynak Kod Güvenlik Raporu",
        "assessment_type": assessment_type.value,
        "organization": "Example Financial Institution (Synthetic)",
        "period_start": "2026-08-12",
        "period_end": "2026-08-12",
        "issued_at": "2026-08-12T12:15:00Z",
        "classification": "RESTRICTED — SYNTHETIC",
        "rules_of_engagement_ref": "attachment://FRX-DEMO-2026-001/approved-roe",
        "in_scope_assets": ["synthetic-source-repository"],
        "excluded_assets": ["production-systems"],
        "tester_organization": "Independent Test Team (Synthetic)",
        "lead_tester": "Synthetic Qualified Tester",
        "independence_declaration": (
            "Synthetic demonstration reviewer is represented as separate from development operations."
        ),
        "tester_qualifications": [
            "qualification-evidence://synthetic/qualified-tester"
        ],
        "methodology": [
            "bounded SARIF 2.1.0 intake",
            "qualified human disposition",
            "digest-bound evidence review",
            "draft report promotion",
        ],
        "executive_summary": (
            "This synthetic workflow demonstrates controlled promotion from machine evidence "
            "into a human-reviewed draft report without contacting a live target."
        ),
        "limitations": [
            "Synthetic evidence only; results cannot be generalized to a real institution."
        ],
        "finding_metadata": {
            confirmed_candidate.finding_id: {
                "affected_assets": [confirmed_candidate.artifact_ref],
                "owner": "Synthetic Engineering Owner",
                "due_date": "2026-09-30",
            }
        },
    }
    report, manifest = build_reviewed_report(
        batch,
        reviews,
        (),
        spec,
        as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc),
    )
    _write_outputs(output_dir, report, manifest, reviews)
    (output_dir / "finding-intake.json").write_text(
        json.dumps(batch.as_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report, manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promote completed qualified finding reviews into a draft FinRedOps report."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Build a draft report from finalized review files.")
    build.add_argument("--intake", required=True, type=Path)
    build.add_argument("--review", action="append", required=True, type=Path)
    build.add_argument("--acceptance", action="append", default=[], type=Path)
    build.add_argument("--spec", required=True, type=Path)
    build.add_argument("--output-dir", required=True, type=Path)

    demo = subparsers.add_parser("demo", help="Run the bundled synthetic promotion workflow.")
    demo.add_argument("--sarif", required=True, type=Path)
    demo.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "build":
        report, manifest = build_from_files(
            intake_path=args.intake,
            review_paths=tuple(args.review),
            acceptance_paths=tuple(args.acceptance),
            spec_path=args.spec,
            output_dir=args.output_dir,
        )
    else:
        report, manifest = build_synthetic_demo(args.sarif, args.output_dir)
    validation = validate_report(report)
    print(
        json.dumps(
            {
                "report_id": report.report_id,
                "report_digest": report.digest(),
                "promoted_findings": len(report.findings),
                "valid": validation.valid,
                "ready_for_issue": validation.ready_for_issue,
                "promotion_digest": manifest["promotion_digest"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
