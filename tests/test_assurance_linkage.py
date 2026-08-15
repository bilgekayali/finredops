from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

from finredops.intake import import_sarif_file
from finredops.promotion import build_reviewed_report
from finredops.review import review_from_draft
from tests.test_promotion import confirmed_draft, false_positive_draft, report_spec

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"


class AssuranceEvidenceLinkageTests(unittest.TestCase):
    def test_review_evidence_flows_into_draft_report(self):
        batch = import_sarif_file(SYNTHETIC_SARIF)
        document = confirmed_draft(batch)
        refs = ["evidence://cyclonedx/source/item", "evidence://asvs/catalog/coverage"]
        document["validation_evidence_refs"] = refs
        confirmed = review_from_draft(document, batch)
        other = review_from_draft(false_positive_draft(batch), batch)
        report, _ = build_reviewed_report(batch, (confirmed, other), (), report_spec(batch, confirmed.finding_id), as_of=datetime(2026, 8, 12, 12, 15, tzinfo=timezone.utc))
        for ref in refs:
            self.assertIn(ref, report.findings[0].evidence_refs)
