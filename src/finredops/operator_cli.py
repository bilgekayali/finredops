"""Unified v0.6 operator commands layered over the existing FinRedOps CLI.

The legacy command surface remains unchanged. This module adds the explicit
qualified-review -> draft-report workflow without moving report issuance or
human approval into automation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .cli import build_parser as legacy_build_parser
from .cli import entrypoint as legacy_entrypoint
from .intake import SarifIntakeError, read_intake_file
from .promotion import (
    ReportPromotionError,
    build_from_files,
    build_synthetic_demo,
)
from .regulations import AssessmentType
from .reporting import validate_report
from .review import (
    QualifiedFindingReview,
    ReviewDisposition,
    ReviewDocumentError,
    build_review_summary,
    read_review_json,
    review_from_document,
)


OPERATOR_COMMANDS = {
    "reviewed-report-spec-template",
    "promote-reviewed-report",
    "demo-reviewed-report",
}


def _command_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"finredops {command}")
    if command == "reviewed-report-spec-template":
        parser.description = (
            "Create a fillable report-promotion specification from a complete "
            "qualified-review set."
        )
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--review", type=Path, action="append", required=True)
        parser.add_argument(
            "--assessment-type",
            choices=[item.value for item in AssessmentType],
            required=True,
        )
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "promote-reviewed-report":
        parser.description = (
            "Promote a complete qualified-review set into a validated draft report."
        )
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--review", type=Path, action="append", required=True)
        parser.add_argument("--acceptance", type=Path, action="append", default=[])
        parser.add_argument("--spec", type=Path, required=True)
        parser.add_argument("--output-dir", type=Path, required=True)
        return parser
    if command == "demo-reviewed-report":
        parser.description = (
            "Reproduce the bundled synthetic SARIF -> review -> draft-report workflow."
        )
        parser.add_argument("--sarif", type=Path, required=True)
        parser.add_argument("--output-dir", type=Path, required=True)
        return parser
    raise ValueError(f"Unknown operator command: {command}")


def _augmented_help() -> str:
    legacy = legacy_build_parser().format_help().rstrip()
    return (
        legacy
        + "\n\nv0.6 operator workflow:\n"
        + "  reviewed-report-spec-template  build a fillable promotion specification\n"
        + "  promote-reviewed-report        create a human-approval-required draft report\n"
        + "  demo-reviewed-report           reproduce the synthetic reviewed-report example\n"
    )


def _load_reviews(
    intake_path: Path, review_paths: Sequence[Path]
) -> tuple[Any, tuple[QualifiedFindingReview, ...]]:
    batch = read_intake_file(intake_path)
    reviews = tuple(
        review_from_document(read_review_json(path), batch) for path in review_paths
    )
    if len({review.finding_id for review in reviews}) != len(reviews):
        raise ReviewDocumentError("More than one review was supplied for the same finding.")
    return batch, reviews


def _spec_template(
    *,
    intake_path: Path,
    review_paths: Sequence[Path],
    assessment_type: AssessmentType,
) -> dict[str, Any]:
    batch, reviews = _load_reviews(intake_path, review_paths)
    if not reviews:
        raise ReviewDocumentError("At least one finalized review is required.")
    as_of = max(review.reviewed_at for review in reviews)
    summary = build_review_summary(
        batch,
        reviews,
        (),
        assessment_type=assessment_type,
        as_of=as_of,
    )
    if not summary.complete:
        raise ReviewDocumentError(
            "A reviewed-report specification requires a disposition for every intake candidate."
        )
    candidate_by_id = {candidate.finding_id: candidate for candidate in batch.findings}
    confirmed = sorted(
        review.finding_id
        for review in reviews
        if review.disposition == ReviewDisposition.CONFIRMED
    )
    return {
        "schema_version": "finredops.reviewed-report-spec.v1",
        "report_id": "TODO",
        "title": "TODO",
        "assessment_type": assessment_type.value,
        "organization": "TODO",
        "period_start": "YYYY-MM-DD",
        "period_end": "YYYY-MM-DD",
        "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
        "classification": "RESTRICTED",
        "rules_of_engagement_ref": "attachment://TODO/approved-roe",
        "in_scope_assets": ["TODO"],
        "excluded_assets": [],
        "tester_organization": "TODO",
        "lead_tester": "TODO",
        "independence_declaration": "TODO",
        "tester_qualifications": ["qualification-evidence://TODO"],
        "methodology": [
            "bounded SARIF 2.1.0 intake",
            "qualified human disposition",
            "digest-bound evidence review",
            "draft report promotion",
        ],
        "executive_summary": "TODO: summarize the reviewed assessment and material risk.",
        "limitations": [
            "TODO: record assessment limitations and evidence constraints."
        ],
        "finding_metadata": {
            finding_id: {
                "affected_assets": [candidate_by_id[finding_id].artifact_ref],
                "owner": "TODO",
                "due_date": "YYYY-MM-DD",
            }
            for finding_id in confirmed
        },
    }


def _contains_template_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        upper = value.upper()
        return "TODO" in upper or "YYYY-MM-DD" in upper
    if isinstance(value, dict):
        return any(_contains_template_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_template_placeholder(item) for item in value)
    return False


def _write_json_exclusive(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def _refuse_output_collisions(output_dir: Path, names: Sequence[str]) -> None:
    if output_dir.exists() and not output_dir.is_dir():
        raise ReportPromotionError("output-dir must be a directory path.")
    collisions = [name for name in names if (output_dir / name).exists()]
    if collisions:
        raise ReportPromotionError(
            f"Refusing to overwrite existing operator outputs: {sorted(collisions)}."
        )


def _run_operator_command(argv: Sequence[str]) -> int:
    command = argv[0]
    args = _command_parser(command).parse_args(list(argv[1:]))
    try:
        if command == "reviewed-report-spec-template":
            document = _spec_template(
                intake_path=args.intake,
                review_paths=tuple(args.review),
                assessment_type=AssessmentType(args.assessment_type),
            )
            _write_json_exclusive(args.output, document)
            print(f"Reviewed-report spec template: {args.output}")
            return 0

        if command == "promote-reviewed-report":
            spec_document = read_review_json(args.spec)
            if _contains_template_placeholder(spec_document):
                raise ReportPromotionError(
                    "Reviewed-report specification still contains template placeholders."
                )
            _refuse_output_collisions(
                args.output_dir,
                ("regulatory-report.json", "regulatory-report.md", "promotion-manifest.json"),
            )
            report, manifest = build_from_files(
                intake_path=args.intake,
                review_paths=tuple(args.review),
                acceptance_paths=tuple(args.acceptance),
                spec_path=args.spec,
                output_dir=args.output_dir,
            )
        else:
            _refuse_output_collisions(
                args.output_dir,
                (
                    "regulatory-report.json",
                    "regulatory-report.md",
                    "promotion-manifest.json",
                    "finding-intake.json",
                    "reviews",
                ),
            )
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
                    "human_approval_required": not validation.ready_for_issue,
                    "promotion_digest": manifest["promotion_digest"],
                    "output_dir": str(args.output_dir),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if validation.valid else 1
    except (
        OSError,
        SarifIntakeError,
        ReviewDocumentError,
        ReportPromotionError,
        ValueError,
    ) as exc:
        print(f"INVALID: {exc}")
        return 1


def entrypoint(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in OPERATOR_COMMANDS:
        return _run_operator_command(raw)
    if raw and raw[0] in {"-h", "--help"}:
        print(_augmented_help())
        return 0
    return legacy_entrypoint(raw)
