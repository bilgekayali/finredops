from __future__ import annotations

import unittest
from dataclasses import replace

from finredops.regulations import AssessmentType, turkey_financial_regulatory_profile
from finredops.reporting import (
    FindingSeverity,
    ReportStatus,
    RetestStatus,
    demo_regulatory_report,
    regulatory_crosswalk,
    render_report_markdown,
    report_from_document,
    report_template_document,
    validate_report,
)

from tests.helpers import NOW


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = turkey_financial_regulatory_profile()
        self.report = demo_regulatory_report(issued_at=NOW)

    def test_demo_report_is_valid_but_requires_human_approval(self) -> None:
        validation = validate_report(self.report, self.profile)
        self.assertTrue(validation.valid)
        self.assertFalse(validation.ready_for_issue)
        self.assertIn("HUMAN_APPROVAL_REQUIRED", {item.code for item in validation.issues})

    def test_missing_mandatory_coverage_is_blocking(self) -> None:
        report = replace(
            self.report,
            coverage_areas=tuple(
                item for item in self.report.coverage_areas if item != "atm"
            ),
        )
        validation = validate_report(report, self.profile)
        self.assertFalse(validation.valid)
        self.assertIn("COVERAGE_MISSING", {item.code for item in validation.issues})

    def test_every_applicable_control_requires_a_conclusion(self) -> None:
        report = replace(
            self.report,
            control_assessments=self.report.control_assessments[:-1],
        )
        validation = validate_report(report, self.profile)
        self.assertIn("CONTROL_NOT_ASSESSED", {item.code for item in validation.issues})

    def test_open_high_risk_requires_owner_and_due_date(self) -> None:
        finding = replace(
            self.report.findings[0],
            severity=FindingSeverity.HIGH,
            owner="",
            due_date="",
        )
        validation = validate_report(replace(self.report, findings=(finding,)), self.profile)
        self.assertIn(
            "HIGH_RISK_OWNERSHIP_REQUIRED", {item.code for item in validation.issues}
        )

    def test_passed_retest_requires_separate_closure_evidence(self) -> None:
        finding = replace(
            self.report.findings[0],
            retest_status=RetestStatus.PASSED,
            retest_date="",
            retest_evidence_refs=(),
        )
        validation = validate_report(replace(self.report, findings=(finding,)), self.profile)
        self.assertIn("RETEST_EVIDENCE_REQUIRED", {item.code for item in validation.issues})

    def test_issued_report_requires_two_distinct_human_approvals(self) -> None:
        report = replace(
            self.report,
            status=ReportStatus.ISSUED,
            human_approvals=("one",),
        )
        self.assertFalse(validate_report(report, self.profile).valid)

    def test_crosswalk_contains_every_applicable_control(self) -> None:
        crosswalk = regulatory_crosswalk(self.report, self.profile)
        self.assertEqual(
            len(crosswalk["controls"]),
            len(self.profile.controls_for(self.report.assessment_type)),
        )
        self.assertTrue(crosswalk["audit_support_only"])

    def test_markdown_is_explicit_about_assurance_limit(self) -> None:
        document = render_report_markdown(self.report, self.profile)
        self.assertIn("Denetim destek taslağıdır", document)
        self.assertIn("TR-BDDK-BSEBY-18-7", document)
        self.assertIn("Yayıma hazır: `hayır`", document)

    def test_all_report_types_have_prefilled_templates(self) -> None:
        for assessment_type in AssessmentType:
            template = report_template_document(assessment_type, self.profile)
            self.assertEqual(template["assessment_type"], assessment_type.value)
            self.assertTrue(template["coverage_areas"])
            self.assertTrue(template["control_assessments"])

    def test_report_json_round_trip_preserves_digest(self) -> None:
        loaded = report_from_document(self.report.as_dict())
        self.assertEqual(loaded.digest(), self.report.digest())

    def test_report_digest_tampering_is_rejected(self) -> None:
        document = self.report.as_dict()
        document["title"] = "Changed after digest"
        with self.assertRaises(ValueError):
            report_from_document(document)


if __name__ == "__main__":
    unittest.main()
