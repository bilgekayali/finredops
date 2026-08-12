from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from finredops.intake import EvidenceIntakeBatch, import_sarif_file
from finredops.promotion import (
    ReportPromotionError,
    build_reviewed_report,
    build_synthetic_demo,
)
from finredops.regulations import AssessmentType
from finredops.reporting import FindingStatus, ReportStatus, validate_report
from finredops.review import review_from_draft, review_template_document


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"
ASSESSMENT_TYPE = AssessmentType.VENDOR_SOURCE_CODE_REVIEW


def confirmed_draft(batch: EvidenceIntakeBatch, index: int = 0) -> dict[str, object]:
    finding = batch.findings[index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT_TYPE)
    document.update(
        {
            "disposition": "confirmed",
            "reviewer_id": "synthetic:qualified-tester",
            "qualification_evidence_ref": "qualification-evidence://synthetic/tester",
            "reviewed_at": "2026-08-12T12:10:00Z",
            "rationale": (
                "The qualified tester correlated the normalized candidate with retained "
                "synthetic evidence and confirmed the reported condition."
            ),
            "validation_evidence_refs": [
                f"evidence://review/{finding.fingerprint}"
            ],
            "final_severity": finding.machine_severity.value,
            "business_impact": (
                "The confirmed condition could weaken the application security boundary "
                "in an equivalent authorized deployment."
            ),
            "recommendation": (
                "Correct the defensive implementation and perform an independent "
                "authorized retest before closure."
            ),
            "control_refs": ["TR-BDDK-BSEBY-22-4-5"],
        }
    )
    return document


def false_positive_draft(batch: EvidenceIntakeBatch, index: int = 1) -> dict[str, object]:
    finding = batch.findings[index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT_TYPE)
    document.update(
        {
            "disposition": "false_positive",
            "reviewer_id": "synthetic:qualified-tester",
            "qualification_evidence_ref": "qualification-evidence://synthetic/tester",
            "reviewed_at": "2026-08-12T12:11:00Z",
            "rationale": (
                "The qualified tester reviewed the retained synthetic evidence and "
                "determined that this candidate is not reportable."
            ),
            "validation_evidence_refs": [
                f"evidence://review/{finding.fingerprint}"
            ],
        }
    )
    return document


def report_spec(batch: EvidenceIntakeBatch, confirmed_id: str) -> dict[str, object]:
    candidate = next(item for item in batch.findings if item.finding_id == confirmed_id)
    return {
        "schema_version": "finredops.reviewed-report-spec.v1",
        "report_id": "FRX-RPT-PROMOTION-TEST-001",
        "title": "Synthetic reviewed source-code report",
        "assessment_type": ASSESSMENT_TYPE.value,
        "organization": "Synthetic Financial Institution",
        "period_start": "2026-08-12",
        "period_end": "2026-08-12",
        "issued_at": "2026-08-12T12:15:00Z",
        "classification": "RESTRICTED — SYNTHETIC",
        "rules_of_engagement_ref": "attachment://synthetic/approved-roe",
        "in_scope_assets": ["synthetic-source-repository"],
        "excluded_assets": ["production-systems"],
        "tester_organization": "Synthetic Independent Test Team",
        "lead_tester": "Synthetic Qualified Tester",
        "independence_declaration": "Synthetic test team is separate from development operations.",
        "tester_qualifications": ["qualification-evidence://synthetic/tester"],
        "methodology": [
            "bounded SARIF intake",
            "qualified review",
            "digest-bound report promotion",
        ],
        "executive_summary": "Synthetic reviewed-finding promotion test.",
        "limitations": ["Synthetic evidence only."],
        "finding_metadata": {
            confirmed_id: {
                "affected_assets": [candidate.artifact_ref],
                "owner": "Synthetic Engineering Owner",
                "due_date": "2026-09-30",
            }
        },
    }


class ReportPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.batch = import_sarif_file(SYNTHETIC_SARIF)
        self.confirmed = review_from_draft(confirmed_draft(self.batch), self.batch)
        self.false_positive = review_from_draft(
            false_positive_draft(self.batch), self.batch
        )
        self.spec = report_spec(self.batch, self.confirmed.finding_id)

    def test_complete_review_set_promotes_confirmed_only(self) -> None:
        report, manifest = build_reviewed_report(
            self.batch,
            (self.confirmed, self.false_positive),
            (),
            self.spec,
            as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(report.status, ReportStatus.DRAFT)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].finding_id, self.confirmed.finding_id)
        self.assertEqual(report.findings[0].status, FindingStatus.OPEN)
        self.assertEqual(manifest["confirmed_count"], 1)
        self.assertEqual(manifest["omitted_nonconfirmed_count"], 1)
        self.assertFalse(manifest["report_issued"])
        self.assertFalse(manifest["automatic_conformance_inference"])

    def test_pending_candidate_blocks_promotion(self) -> None:
        with self.assertRaises(ReportPromotionError):
            build_reviewed_report(
                self.batch,
                (self.confirmed,),
                (),
                self.spec,
                as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc),
            )

    def test_asset_and_owner_metadata_is_exact_and_fail_closed(self) -> None:
        changed = dict(self.spec)
        changed["finding_metadata"] = {}
        with self.assertRaises(ReportPromotionError):
            build_reviewed_report(
                self.batch,
                (self.confirmed, self.false_positive),
                (),
                changed,
                as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc),
            )

    def test_promoted_report_is_valid_but_not_ready_for_issue(self) -> None:
        report, _ = build_reviewed_report(
            self.batch,
            (self.confirmed, self.false_positive),
            (),
            self.spec,
            as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc),
        )
        validation = validate_report(report)
        self.assertTrue(validation.valid)
        self.assertFalse(validation.ready_for_issue)
        self.assertTrue(
            any(item.code == "HUMAN_APPROVAL_REQUIRED" for item in validation.issues)
        )

    def test_synthetic_demo_writes_traceable_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reviewed"
            report, manifest = build_synthetic_demo(SYNTHETIC_SARIF, output)
            self.assertEqual(report.status, ReportStatus.DRAFT)
            self.assertTrue((output / "finding-intake.json").is_file())
            self.assertTrue((output / "regulatory-report.json").is_file())
            self.assertTrue((output / "regulatory-report.md").is_file())
            self.assertTrue((output / "promotion-manifest.json").is_file())
            self.assertEqual(len(list((output / "reviews").glob("*.json"))), 2)
            self.assertEqual(manifest["promoted_finding_ids"], [report.findings[0].finding_id])


if __name__ == "__main__":
    unittest.main()
