from __future__ import annotations

import unittest

from finredops.cvss40 import Cvss40ValidationError, validate_cvss40


FIRST_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L"


class AssuranceCompletenessTests(unittest.TestCase):
    def test_first_cvss40_example(self) -> None:
        result = validate_cvss40(FIRST_VECTOR, declared_score=8.7, declared_severity="HIGH")
        self.assertEqual(result.score, 8.7)
        self.assertEqual(result.severity, "high")
        self.assertFalse(result.financial_business_impact_inferred)

    def test_cvss40_rejects_other_version(self) -> None:
        with self.assertRaises(Cvss40ValidationError):
            validate_cvss40("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
