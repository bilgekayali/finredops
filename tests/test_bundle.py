from __future__ import annotations

import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from finredops.bundle import BundlePurpose, build_audit_bundle, verify_audit_bundle
from finredops.demo import build_demo_assurance_snapshot, build_demo_service
from finredops.diffing import compare_reports

from tests.helpers import NOW


class AuditBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service, self.engagement_id = build_demo_service(now=NOW)
        _, self.report, self.applicability, self.evidence = (
            build_demo_assurance_snapshot(
                self.service,
                self.engagement_id,
                now=NOW,
            )
        )

    def _build(self, path: Path):
        return build_audit_bundle(
            path,
            report=self.report,
            applicability=self.applicability,
            evidence=self.evidence,
            audit=self.service.audit,
            created_at=NOW,
            purpose=BundlePurpose.HUMAN_REVIEW,
            profile=self.service.regulatory_profile,
        )

    def test_bundle_is_deterministic_and_verifies_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            result = self._build(first)
            self._build(second)
            verification = verify_audit_bundle(first)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(verification.valid, verification.errors)
            self.assertFalse(result.ready_for_submission)
            self.assertIn("not issued", " ".join(result.blockers))

    def test_tampered_entry_fails_digest_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.zip"
            tampered = Path(directory) / "tampered.zip"
            self._build(original)
            with zipfile.ZipFile(original) as source:
                documents = {name: source.read(name) for name in source.namelist()}
            documents["report.md"] += b"\nchanged after packaging\n"
            with zipfile.ZipFile(
                tampered,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as target:
                for name, body in documents.items():
                    target.writestr(name, body)
            verification = verify_audit_bundle(tampered)
            self.assertFalse(verification.valid)
            self.assertIn("Digest mismatch", " ".join(verification.errors))

    def test_draft_cannot_be_labeled_regulatory_submission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                build_audit_bundle(
                    Path(directory) / "submission.zip",
                    report=self.report,
                    applicability=self.applicability,
                    evidence=self.evidence,
                    audit=self.service.audit,
                    created_at=NOW,
                    purpose=BundlePurpose.REGULATORY_SUBMISSION,
                    profile=self.service.regulatory_profile,
                )

    def test_optional_report_delta_is_bound_to_current_report(self) -> None:
        baseline = replace(
            self.report,
            report_id="FRX-RPT-2026-BASELINE",
            issued_at=NOW - timedelta(days=1),
        )
        delta = compare_reports(baseline, self.report)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "with-delta.zip"
            build_audit_bundle(
                path,
                report=self.report,
                applicability=self.applicability,
                evidence=self.evidence,
                audit=self.service.audit,
                created_at=NOW,
                purpose=BundlePurpose.HUMAN_REVIEW,
                profile=self.service.regulatory_profile,
                delta=delta,
            )
            verification = verify_audit_bundle(path)
        self.assertTrue(verification.valid, verification.errors)


if __name__ == "__main__":
    unittest.main()
