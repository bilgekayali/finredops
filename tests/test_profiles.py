from __future__ import annotations

import unittest
from dataclasses import replace

from finredops.models import AssetKind, DataClassification, Environment, ScopeAsset
from finredops.profiles import regulated_financial_profile

from tests.helpers import make_engagement


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = regulated_financial_profile()

    def test_safe_synthetic_engagement_passes(self) -> None:
        report = self.profile.lint(make_engagement())
        self.assertTrue(report.allowed)
        self.assertEqual(report.blocking_count, 0)

    def test_broad_network_scope_is_blocked(self) -> None:
        engagement = replace(
            make_engagement(),
            assets=(
                ScopeAsset(
                    "NET-1",
                    AssetKind.CIDR,
                    "192.0.2.0/24",
                    Environment.TEST,
                    DataClassification.INTERNAL,
                    "payments",
                ),
            ),
        )
        report = self.profile.lint(engagement)
        self.assertFalse(report.allowed)
        self.assertIn("PROFILE_SCOPE_TOO_BROAD", {item.code for item in report.findings})

    def test_scope_exclusion_overlap_is_blocked(self) -> None:
        engagement = make_engagement()
        overlap = replace(engagement.assets[0], asset_id="A-X-2")
        report = self.profile.lint(replace(engagement, excluded_assets=(overlap,)))
        self.assertFalse(report.allowed)
        self.assertIn(
            "PROFILE_SCOPE_EXCLUSION_OVERLAP", {item.code for item in report.findings}
        )

    def test_production_controlled_action_is_blocked(self) -> None:
        engagement = make_engagement()
        production = replace(
            engagement.assets[0], environment=Environment.PRODUCTION
        )
        report = self.profile.lint(
            replace(
                engagement,
                assets=(production,),
                emergency_contacts=("one@example.test", "two@example.test"),
            )
        )
        self.assertIn(
            "PROFILE_PRODUCTION_ACTION_DENIED", {item.code for item in report.findings}
        )

    def test_profile_digest_is_stable(self) -> None:
        self.assertEqual(self.profile.digest(), regulated_financial_profile().digest())


if __name__ == "__main__":
    unittest.main()
