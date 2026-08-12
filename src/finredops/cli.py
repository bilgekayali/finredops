"""Command-line interface for the FinRedOps demonstration control plane."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .applicability import ApplicabilityAssessment
from .api import serve_read_only_api
from .audit import AuditChain
from .bundle import BundlePurpose, build_audit_bundle, verify_audit_bundle
from .custody import EvidenceManifest
from .demo import build_demo_assurance_snapshot, build_demo_service, write_demo
from .diffing import compare_reports
from .intake import SarifIntakeError, import_sarif_file, read_intake_file
from .planner import GuardedPlanningGateway, PlanValidationError
from .profiles import regulated_financial_profile
from .regulations import AssessmentType
from .reporting import (
    ReportDocumentError,
    render_report_markdown,
    report_from_document,
    report_template_document,
    validate_report,
)
from .serialization import (
    DocumentValidationError,
    engagement_from_document,
    read_json_document,
)
from .store import SQLiteGovernanceStore
from .models import parse_datetime, utc_now


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finredops",
        description="Governance-first simulation and approval-gated controlled validation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Generate a synthetic dashboard and audit trail.")
    demo.add_argument("--output", type=Path, default=Path("demo-output"))
    verify = subparsers.add_parser("verify-audit", help="Verify a generated audit hash chain.")
    verify.add_argument("path", type=Path)
    verify_bundle = subparsers.add_parser(
        "verify-bundle", help="Verify an audit dossier without extracting it."
    )
    verify_bundle.add_argument("path", type=Path)
    serve = subparsers.add_parser("serve", help="Serve the synthetic dashboard locally.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    validate_engagement = subparsers.add_parser(
        "validate-engagement", help="Validate an engagement and institution preflight."
    )
    validate_engagement.add_argument("path", type=Path)
    validate_plan = subparsers.add_parser(
        "validate-plan", help="Validate a structured AI plan against an engagement."
    )
    validate_plan.add_argument("path", type=Path)
    validate_plan.add_argument("--engagement", type=Path, required=True)
    report_template = subparsers.add_parser(
        "report-template", help="Create a regulatory assessment report template."
    )
    report_template.add_argument(
        "--type", choices=[item.value for item in AssessmentType], required=True
    )
    report_template.add_argument("--output", type=Path, required=True)
    validate_report_command = subparsers.add_parser(
        "validate-report", help="Validate a regulatory audit-support report."
    )
    validate_report_command.add_argument("path", type=Path)
    render_report = subparsers.add_parser(
        "render-report", help="Validate report JSON and render reviewable Markdown."
    )
    render_report.add_argument("path", type=Path)
    render_report.add_argument("--output", type=Path, required=True)
    compare = subparsers.add_parser(
        "compare-reports", help="Create a traceable finding and control delta."
    )
    compare.add_argument("baseline", type=Path)
    compare.add_argument("current", type=Path)
    compare.add_argument("--output", type=Path)
    validate_applicability = subparsers.add_parser(
        "validate-applicability", help="Verify a human-confirmed applicability document."
    )
    validate_applicability.add_argument("path", type=Path)
    validate_evidence = subparsers.add_parser(
        "validate-evidence-manifest", help="Verify evidence metadata and chain of custody."
    )
    validate_evidence.add_argument("path", type=Path)
    build_bundle = subparsers.add_parser(
        "build-bundle", help="Build a deterministic metadata-only audit dossier."
    )
    build_bundle.add_argument("--report", type=Path, required=True)
    build_bundle.add_argument("--applicability", type=Path, required=True)
    build_bundle.add_argument("--evidence-manifest", type=Path, required=True)
    build_bundle.add_argument("--audit", type=Path, required=True)
    build_bundle.add_argument("--output", type=Path, required=True)
    build_bundle.add_argument(
        "--purpose",
        choices=[item.value for item in BundlePurpose],
        default=BundlePurpose.HUMAN_REVIEW.value,
    )
    build_bundle.add_argument(
        "--created-at",
        help="Timezone-aware ISO-8601 timestamp; defaults to the current UTC time.",
    )
    verify_store = subparsers.add_parser(
        "verify-store", help="Verify an engagement's persisted audit chain."
    )
    verify_store.add_argument("database", type=Path)
    verify_store.add_argument("engagement_id")
    import_sarif = subparsers.add_parser(
        "import-sarif",
        help="Normalize bounded SARIF 2.1.0 into human-review finding candidates.",
    )
    import_sarif.add_argument("path", type=Path)
    import_sarif.add_argument("--output", type=Path, required=True)
    validate_intake = subparsers.add_parser(
        "validate-intake",
        help="Verify a canonical finding-intake document and its digest.",
    )
    validate_intake.add_argument("path", type=Path)
    return parser


def entrypoint(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        paths = write_demo(args.output)
        labels = {
            "dashboard": "Dashboard",
            "audit": "Audit log",
            "snapshot": "Snapshot",
            "database": "SQLite store",
            "report_markdown": "Regulatory report",
            "report_json": "Report JSON",
            "crosswalk": "Regulatory crosswalk",
            "applicability": "Applicability assessment",
            "evidence_manifest": "Evidence manifest",
            "audit_bundle": "Audit dossier",
            "bundle_result": "Dossier build result",
            "bundle_verification": "Dossier verification",
        }
        for key, label in labels.items():
            print(f"{label}: {paths[key]}")
        return 0
    if args.command == "verify-audit":
        chain = AuditChain.read(args.path)
        valid, errors = chain.verify()
        if valid:
            print(f"VALID: {len(chain.events)} audit events form an intact hash chain.")
            return 0
        for error in errors:
            print(f"INVALID: {error}")
        return 1
    if args.command == "verify-bundle":
        result = verify_audit_bundle(args.path)
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return 0 if result.valid else 1
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise SystemExit("Port must be between 1 and 65535.")
        now = utc_now()
        service, engagement_id = build_demo_service(now=now)
        snapshot, _, _, _ = build_demo_assurance_snapshot(
            service, engagement_id, now=now
        )
        serve_read_only_api(snapshot, host=args.host, port=args.port)
        return 0
    if args.command == "validate-engagement":
        try:
            engagement = engagement_from_document(read_json_document(args.path))
            report = regulated_financial_profile().lint(engagement)
        except (DocumentValidationError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
        return 0 if report.allowed else 1
    if args.command == "validate-plan":
        try:
            engagement = engagement_from_document(read_json_document(args.engagement))
            plan = read_json_document(args.path, maximum_bytes=64_000)
            proposals = GuardedPlanningGateway().parse(
                plan,
                engagement=engagement,
                proposed_by="cli.validation",
                now=utc_now(),
            )
        except (DocumentValidationError, PlanValidationError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(f"VALID: {len(proposals)} structured proposals use the closed action catalog.")
        return 0
    if args.command == "report-template":
        document = report_template_document(AssessmentType(args.type))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Template: {args.output}")
        return 0
    if args.command in {"validate-report", "render-report"}:
        try:
            report = report_from_document(
                read_json_document(args.path, maximum_bytes=2_000_000)
            )
            validation = validate_report(report)
        except (DocumentValidationError, ReportDocumentError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        if not validation.valid:
            print(json.dumps(validation.as_dict(), ensure_ascii=False, indent=2))
            return 1
        if args.command == "validate-report":
            print(json.dumps(validation.as_dict(), ensure_ascii=False, indent=2))
            return 0
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render_report_markdown(report), encoding="utf-8")
        print(f"Rendered report: {args.output}")
        return 0
    if args.command == "compare-reports":
        try:
            baseline = report_from_document(
                read_json_document(args.baseline, maximum_bytes=2_000_000)
            )
            current = report_from_document(
                read_json_document(args.current, maximum_bytes=2_000_000)
            )
            document = compare_reports(baseline, current).as_dict()
        except (DocumentValidationError, ReportDocumentError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        rendered = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Report delta: {args.output}")
        else:
            print(rendered, end="")
        return 0
    if args.command == "validate-applicability":
        try:
            document = read_json_document(args.path, maximum_bytes=1_000_000)
            if not isinstance(document, dict):
                raise ValueError("Applicability document must be a JSON object.")
            applicability = ApplicabilityAssessment.from_dict(document)
        except (DocumentValidationError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(json.dumps(applicability.as_dict(), ensure_ascii=False, indent=2))
        return 0 if applicability.ready_for_audit else 1
    if args.command == "validate-evidence-manifest":
        try:
            document = read_json_document(args.path, maximum_bytes=5_000_000)
            if not isinstance(document, dict):
                raise ValueError("Evidence manifest must be a JSON object.")
            manifest = EvidenceManifest.from_dict(document)
            valid, errors = manifest.verify()
        except (DocumentValidationError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(json.dumps(manifest.as_dict(), ensure_ascii=False, indent=2))
        if errors:
            return 1
        return 0 if valid else 1
    if args.command == "build-bundle":
        try:
            report = report_from_document(
                read_json_document(args.report, maximum_bytes=2_000_000)
            )
            applicability_document = read_json_document(
                args.applicability, maximum_bytes=1_000_000
            )
            evidence_document = read_json_document(
                args.evidence_manifest, maximum_bytes=5_000_000
            )
            if not isinstance(applicability_document, dict) or not isinstance(
                evidence_document, dict
            ):
                raise ValueError("Applicability and evidence documents must be objects.")
            applicability = ApplicabilityAssessment.from_dict(applicability_document)
            evidence = EvidenceManifest.from_dict(evidence_document)
            created_at: datetime = (
                parse_datetime(args.created_at) if args.created_at else utc_now()
            )
            result = build_audit_bundle(
                args.output,
                report=report,
                applicability=applicability,
                evidence=evidence,
                audit=AuditChain.read(args.audit),
                created_at=created_at,
                purpose=BundlePurpose(args.purpose),
            )
        except (
            DocumentValidationError,
            ReportDocumentError,
            OSError,
            ValueError,
        ) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "verify-store":
        try:
            with SQLiteGovernanceStore(args.database) as store:
                valid, errors = store.verify_persisted_audit(args.engagement_id)
        except (OSError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        if valid:
            print(f"VALID: persisted audit chain for {args.engagement_id} is intact.")
            return 0
        for error in errors:
            print(f"INVALID: {error}")
        return 1
    if args.command == "import-sarif":
        try:
            if args.path.resolve() == args.output.resolve():
                raise SarifIntakeError("SARIF source and canonical output must be different files.")
            batch = import_sarif_file(args.path)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(batch.as_dict(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except (OSError, SarifIntakeError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(
            f"Intake: {args.output} "
            f"({len(batch.findings)} review candidates, "
            f"{batch.duplicate_result_count} duplicates)"
        )
        return 0
    if args.command == "validate-intake":
        try:
            batch = read_intake_file(args.path)
        except (SarifIntakeError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(
            f"VALID: {batch.batch_id} contains {len(batch.findings)} "
            "human-review candidates and no embedded raw source."
        )
        return 0
    return 2
