from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from finredops.audit import AuditChain
from finredops.demo import build_demo_service, write_demo
from finredops.models import Role

from tests.helpers import NOW


class ServiceIntegrationTests(unittest.TestCase):
    def test_demo_executes_only_supported_synthetic_actions(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        self.assertTrue(snapshot["simulation_only"])
        self.assertEqual(len(snapshot["proposals"]), 4)
        self.assertEqual(len(snapshot["receipts"]), 3)
        denied = [item for item in snapshot["decisions"].values() if not item["allowed"]]
        self.assertEqual(len(denied), 1)
        self.assertTrue(
            all(receipt["evidence"]["network_activity"] is False for receipt in snapshot["receipts"].values())
        )
        self.assertEqual(service.audit.verify(), (True, ()))

    def test_pause_blocks_subsequent_execution(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        service.pause_engagement(
            engagement_id,
            actor_id="control",
            role=Role.CONTROL_TEAM,
            now=NOW,
        )
        proposal_id = next(iter(service.proposals))
        decision, receipt = service.execute_proposal(
            proposal_id,
            actor_id="operator",
            role=Role.OPERATOR,
            now=NOW,
        )
        self.assertFalse(decision.allowed)
        self.assertIsNone(receipt)
        self.assertIn("Emergency stop", " ".join(decision.reasons))

    def test_generated_artifacts_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_demo(Path(directory), now=NOW)
            self.assertIn("SIMULATION-ONLY RUNNER", paths["dashboard"].read_text())
            self.assertIn("SPK", paths["report_markdown"].read_text())
            self.assertTrue(paths["database"].exists())
            self.assertTrue(paths["crosswalk"].exists())
            valid, errors = AuditChain.read(paths["audit"]).verify()
        self.assertTrue(valid, errors)


if __name__ == "__main__":
    unittest.main()
