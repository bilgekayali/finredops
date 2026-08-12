"""Command-line interface for the FinRedOps demonstration control plane."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .api import serve_read_only_api
from .audit import AuditChain
from .demo import build_demo_service, write_demo
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
from .models import utc_now


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finredops",
        description="Governance-first, simulation-only security testing orchestration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="Generate a synthetic dashboard and audit trail.")
    demo.add_argument("--output", type=Path, default=Path("demo-output"))
    verify = subparsers.add_parser("verify-audit", help="Verify a generated audit hash chain.")
    verify.add_argument("path", type=Path)
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
    verify_store = subparsers.add_parser(
        "verify-store", help="Verify an engagement's persisted audit chain."
    )
    verify_store.add_argument("database", type=Path)
    verify_store.add_argument("engagement_id")
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
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            raise SystemExit("Port must be between 1 and 65535.")
        service, engagement_id = build_demo_service()
        serve_read_only_api(service.snapshot(engagement_id), host=args.host, port=args.port)
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
    return 2
