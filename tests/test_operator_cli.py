from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from finredops.operator_cli import entrypoint
from finredops.promotion import build_synthetic_demo
from finredops.reporting import report_from_document, validate_report
from finredops.serialization import read_json_document


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"


class OperatorCliTests(unittest.TestCase):
    def test_augmented_help_surfaces_v06_commands(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = entrypoint(["--help"])
        self.assertEqual(result, 0)
        text = output.getvalue()
        self.assertIn("reviewed-report-spec-template", text)
        self.assertIn("promote-reviewed-report", text)
        self.assertIn("demo-reviewed-report", text)

    def test_demo_reviewed_report_is_reproducible_and_draft_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "reviewed"
            captured = io.StringIO()
            with redirect_stdout(captured):
                result = entrypoint(
                    [
                        "demo-reviewed-report",
                        "--sarif",
                        str(SYNTHETIC_SARIF),
                        "--output-dir",
                        str(output_dir),
                    ]
                )
            self.assertEqual(result, 0)
            summary = json.loads(captured.getvalue())
            self.assertTrue(summary["valid"])
            self.assertFalse(summary["ready_for_issue"])
            self.assertTrue(summary["human_approval_required"])
            self.assertTrue((output_dir / "regulatory-report.md").is_file())
            self.assertTrue((output_dir / "promotion-manifest.json").is_file())

            report = report_from_document(
                read_json_document(output_dir / "regulatory-report.json")
            )
            validation = validate_report(report)
            self.assertTrue(validation.valid)
            self.assertFalse(validation.ready_for_issue)

            with redirect_stdout(io.StringIO()):
                repeated = entrypoint(
                    [
                        "demo-reviewed-report",
                        "--sarif",
                        str(SYNTHETIC_SARIF),
                        "--output-dir",
                        str(output_dir),
                    ]
                )
            self.assertEqual(repeated, 1)

    def test_spec_template_and_promote_command_form_end_to_end_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "seed"
            build_synthetic_demo(SYNTHETIC_SARIF, seed)
            review_paths = sorted((seed / "reviews").glob("*.json"))
            spec_path = root / "reviewed-report-spec.json"

            template_args = [
                "reviewed-report-spec-template",
                "--intake",
                str(seed / "finding-intake.json"),
                "--assessment-type",
                "vendor_source_code_review",
                "--output",
                str(spec_path),
            ]
            for path in review_paths:
                template_args.extend(["--review", str(path)])
            with redirect_stdout(io.StringIO()):
                template_result = entrypoint(template_args)
            self.assertEqual(template_result, 0)

            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            spec.update(
                {
                    "report_id": "FRX-RPT-OPERATOR-001",
                    "title": "Synthetic operator workflow report",
                    "organization": "Synthetic Financial Institution",
                    "period_start": "2026-08-12",
                    "period_end": "2026-08-12",
                    "issued_at": "2026-08-12T12:15:00Z",
                    "classification": "RESTRICTED — SYNTHETIC",
                    "rules_of_engagement_ref": "attachment://synthetic/approved-roe",
                    "in_scope_assets": ["synthetic-source-repository"],
                    "tester_organization": "Synthetic Independent Test Team",
                    "lead_tester": "Synthetic Qualified Tester",
                    "independence_declaration": (
                        "Synthetic test team is separate from development operations."
                    ),
                    "tester_qualifications": [
                        "qualification-evidence://synthetic/qualified-tester"
                    ],
                    "executive_summary": (
                        "Synthetic end-to-end operator workflow validation."
                    ),
                    "limitations": ["Synthetic evidence only."],
                }
            )
            for metadata in spec["finding_metadata"].values():
                metadata["owner"] = "Synthetic Engineering Owner"
                metadata["due_date"] = "2026-09-30"
            spec_path.write_text(
                json.dumps(spec, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            output_dir = root / "promoted"
            promote_args = [
                "promote-reviewed-report",
                "--intake",
                str(seed / "finding-intake.json"),
                "--spec",
                str(spec_path),
                "--output-dir",
                str(output_dir),
            ]
            for path in review_paths:
                promote_args.extend(["--review", str(path)])
            captured = io.StringIO()
            with redirect_stdout(captured):
                promote_result = entrypoint(promote_args)
            self.assertEqual(promote_result, 0)
            result = json.loads(captured.getvalue())
            self.assertEqual(result["promoted_findings"], 1)
            self.assertTrue(result["valid"])
            self.assertFalse(result["ready_for_issue"])

    def test_unfinished_spec_template_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "seed"
            build_synthetic_demo(SYNTHETIC_SARIF, seed)
            review_paths = sorted((seed / "reviews").glob("*.json"))
            spec_path = root / "spec.json"
            template_args = [
                "reviewed-report-spec-template",
                "--intake",
                str(seed / "finding-intake.json"),
                "--assessment-type",
                "vendor_source_code_review",
                "--output",
                str(spec_path),
            ]
            for path in review_paths:
                template_args.extend(["--review", str(path)])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(entrypoint(template_args), 0)

            promote_args = [
                "promote-reviewed-report",
                "--intake",
                str(seed / "finding-intake.json"),
                "--spec",
                str(spec_path),
                "--output-dir",
                str(root / "blocked"),
            ]
            for path in review_paths:
                promote_args.extend(["--review", str(path)])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(entrypoint(promote_args), 1)


if __name__ == "__main__":
    unittest.main()
