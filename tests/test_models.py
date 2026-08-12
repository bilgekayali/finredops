from __future__ import annotations

import unittest
from dataclasses import replace

from finredops.models import (
    AssetKind,
    DataClassification,
    EngagementStatus,
    Environment,
    ScopeAsset,
    canonical_hostname,
)

from tests.helpers import make_engagement
from tests.helpers import make_proposal


class ModelTests(unittest.TestCase):
    def test_hostname_is_canonical_and_exact(self) -> None:
        self.assertEqual(canonical_hostname("Payments.Example.Test."), "payments.example.test")
        with self.assertRaises(ValueError):
            canonical_hostname("*.example.test")
        with self.assertRaises(ValueError):
            canonical_hostname("localhost")

    def test_cidr_contains_only_addresses_in_network(self) -> None:
        asset = ScopeAsset(
            asset_id="NET-1",
            kind=AssetKind.CIDR,
            value="192.0.2.7/28",
            environment=Environment.LAB,
            data_classification=DataClassification.INTERNAL,
            critical_function="synthetic",
        )
        self.assertEqual(asset.value, "192.0.2.0/28")
        self.assertTrue(asset.contains("192.0.2.10"))
        self.assertFalse(asset.contains("192.0.2.20"))

    def test_status_does_not_change_approval_digest(self) -> None:
        draft = make_engagement(status=EngagementStatus.DRAFT)
        approved = replace(draft, status=EngagementStatus.APPROVED)
        self.assertEqual(draft.digest(), approved.digest())

    def test_proposal_parameters_are_deeply_immutable(self) -> None:
        source = {"expected_control": "TEST-01", "evidence_reference": "SYNTH-1"}
        proposal = make_proposal(parameters=source)
        original_digest = proposal.digest()
        source["expected_control"] = "CHANGED"
        self.assertEqual(proposal.parameters["expected_control"], "TEST-01")
        self.assertEqual(proposal.digest(), original_digest)
        with self.assertRaises(TypeError):
            proposal.parameters["expected_control"] = "NOPE"  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
