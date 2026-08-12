from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from finredops.diffing import ReportDelta, compare_reports
from finredops.reporting import (
    ControlConclusion,
    FindingSeverity,
    FindingStatus,
    RetestStatus,
    demo_regulatory_report,
)

from tests.helpers import NOW


class ReportDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = demo_regulatory_report(issued_at=NOW)

    def test_closure_and_control_improvement_are_visible(self) -> None:
        finding = replace(
            self.baseline.findings[0],
            severity=FindingSeverity.LOW,
            status=FindingStatus.CLOSED,
            retest_status=RetestStatus.PASSED,
            retest_date="2026-08-13",
            retest_evidence_refs=("evidence://FRX-DEMO-2026-001/retest/001",),
        )
        controls = tuple(
            replace(item, conclusion=ControlConclusion.CONFORMS)
            if item.control_id == "TR-BDDK-GEN-2012-1"
            else item
            for item in self.baseline.control_assessments
        )
        current = replace(
            self.baseline,
            report_id="FRX-RPT-2026-002",
            issued_at=NOW + timedelta(days=1),
            findings=(finding,),
            control_assessments=controls,
        )
        delta = compare_reports(self.baseline, current)
        self.assertEqual(delta.closed_findings, ("FRX-SYN-001",))
        self.assertEqual(delta.severity_decreases[0].current, "low")
        self.assertIn(
            "TR-BDDK-GEN-2012-1",
            {item.item_id for item in delta.control_improvements},
        )
        self.assertFalse(delta.has_regressions)
        self.assertEqual(ReportDelta.from_dict(delta.as_dict()).digest(), delta.digest())

        document = delta.as_dict()
        document["closed_findings"] = []
        with self.assertRaises(ValueError):
            ReportDelta.from_dict(document)

    def test_reopened_and_new_findings_are_regressions(self) -> None:
        closed = replace(self.baseline.findings[0], status=FindingStatus.CLOSED)
        baseline = replace(self.baseline, findings=(closed,))
        new_finding = replace(
            self.baseline.findings[0],
            finding_id="FRX-SYN-002",
            title="Second synthetic finding",
        )
        current = replace(
            self.baseline,
            report_id="FRX-RPT-2026-002",
            issued_at=NOW + timedelta(days=1),
            findings=(self.baseline.findings[0], new_finding),
        )
        delta = compare_reports(baseline, current)
        self.assertEqual(delta.reopened_findings, ("FRX-SYN-001",))
        self.assertEqual(delta.new_findings, ("FRX-SYN-002",))
        self.assertTrue(delta.has_regressions)

    def test_reports_from_different_organizations_are_rejected(self) -> None:
        current = replace(
            self.baseline,
            organization="Another Institution",
            issued_at=NOW + timedelta(days=1),
        )
        with self.assertRaises(ValueError):
            compare_reports(self.baseline, current)


if __name__ == "__main__":
    unittest.main()
