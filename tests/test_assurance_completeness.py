from __future__ import annotations

import unittest

from finredops.cvss40 import Cvss40ValidationError, validate_cvss40
from finredops.supply_chain import SupplyChainIntakeError, import_cyclonedx_document

FIRST_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L"


class AssuranceCompletenessTests(unittest.TestCase):
    def test_first_cvss40_example(self):
        result = validate_cvss40(FIRST_VECTOR, declared_score=8.7, declared_severity="HIGH")
        self.assertEqual(result.score, 8.7)
        self.assertEqual(result.severity, "high")
        self.assertFalse(result.financial_business_impact_inferred)

    def test_cvss40_rejects_other_version(self):
        with self.assertRaises(Cvss40ValidationError):
            validate_cvss40("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_inventory_version_pin(self):
        document = {"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"library","bom-ref":"component-synthetic-001","name":"synthetic-library"}]}
        batch = import_cyclonedx_document(document)
        self.assertEqual(batch.source_version, "1.7")
        self.assertEqual(len(batch.components), 1)
        self.assertEqual(batch.findings, ())
        self.assertTrue(batch.human_review_required)
        self.assertFalse(batch.raw_source_embedded)
        self.assertFalse(batch.regulatory_applicability_inferred)

    def test_inventory_other_version_fails_closed(self):
        document = {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}
        with self.assertRaises(SupplyChainIntakeError):
            import_cyclonedx_document(document)
