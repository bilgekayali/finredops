from __future__ import annotations

import unittest
from dataclasses import replace

from finredops.applicability import (
    ApplicabilityAssessment,
    ApplicabilityDecision,
    assess_applicability,
    demo_applicability_context,
)
from finredops.regulations import Authority, turkey_financial_regulatory_profile

from tests.helpers import NOW


class ApplicabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = turkey_financial_regulatory_profile()
        self.context = demo_applicability_context(confirmed_at=NOW)

    def test_confirmed_demo_includes_applicable_tse_controls(self) -> None:
        assessment = assess_applicability(self.context, self.profile)
        tse = [item for item in assessment.decisions if item.authority == Authority.TSE]
        self.assertEqual(len(tse), 3)
        self.assertTrue(
            all(item.decision == ApplicabilityDecision.APPLICABLE for item in tse)
        )
        self.assertTrue(assessment.ready_for_audit)

    def test_unknown_tse_scope_fails_closed(self) -> None:
        context = replace(self.context, tse_ts13638_in_scope=None)
        assessment = assess_applicability(context, self.profile)
        tse = [item for item in assessment.decisions if item.authority == Authority.TSE]
        self.assertFalse(assessment.ready_for_audit)
        self.assertTrue(
            all(
                item.decision == ApplicabilityDecision.REQUIRES_CONFIRMATION
                for item in tse
            )
        )

    def test_round_trip_preserves_digest(self) -> None:
        assessment = assess_applicability(self.context, self.profile)
        loaded = ApplicabilityAssessment.from_dict(assessment.as_dict())
        self.assertEqual(loaded.digest(), assessment.digest())

    def test_string_boolean_is_rejected(self) -> None:
        document = assess_applicability(self.context, self.profile).as_dict()
        document["context"]["tse_ts13638_in_scope"] = "true"
        with self.assertRaises(ValueError):
            ApplicabilityAssessment.from_dict(document)

    def test_digest_tampering_is_rejected(self) -> None:
        document = assess_applicability(self.context, self.profile).as_dict()
        document["context"]["rationale"] = "Changed after approval"
        with self.assertRaises(ValueError):
            ApplicabilityAssessment.from_dict(document)


if __name__ == "__main__":
    unittest.main()
