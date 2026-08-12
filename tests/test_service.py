from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from finredops.audit import AuditChain
from finredops.bundle import verify_audit_bundle
from finredops.custody import EvidenceManifest
from finredops.demo import build_demo_service, write_demo
from finredops.models import ExecutionStatus, Role
from finredops.service import FinRedOpsService
from finredops.validation import ControlledValidationRunner, ProbeResponse

from tests.helpers import (
    NOW,
    controlled_proposal_approvals,
    make_engagement,
    make_proposal,
)


class _ServiceProbe:
    def head(self, **_: object) -> ProbeResponse:
        return ProbeResponse(
            status_code=200,
            headers=(),
            tls_version="TLSv1.3",
            certificate_not_after=NOW + timedelta(days=90),
            peer_address="192.0.2.10",
        )


class ServiceIntegrationTests(unittest.TestCase):
    def test_explicit_controlled_runner_generates_draft_findings(self) -> None:
        service = FinRedOpsService(
            controlled_runner=ControlledValidationRunner(_ServiceProbe())
        )
        engagement = make_engagement()
        proposal = make_proposal(
            engagement,
            action_id="http.security_posture.validate",
            parameters={"change_reference": "CHG-SYNTH-001"},
        )
        service.engagements[engagement.engagement_id] = engagement
        service.preflight_reports[engagement.engagement_id] = service.profile.lint(
            engagement
        )
        service.proposals[proposal.proposal_id] = proposal
        service.approvals.extend(controlled_proposal_approvals(proposal))

        decision, receipt = service.execute_proposal(
            proposal.proposal_id,
            actor_id="operator",
            role=Role.OPERATOR,
            now=NOW,
        )
        self.assertTrue(decision.allowed, decision.reasons)
        self.assertIsNotNone(receipt)
        assert receipt is not None
        self.assertEqual(receipt.status, ExecutionStatus.VALIDATED)
        snapshot = service.snapshot(engagement.engagement_id)
        self.assertFalse(snapshot["simulation_only"])
        self.assertTrue(snapshot["execution_capabilities"]["controlled_validation"])
        self.assertGreater(len(snapshot["generated_findings"][proposal.proposal_id]), 0)
        self.assertEqual(service.audit.verify(), (True, ()))

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
            self.assertIn("SIMULATION-ONLY DEFAULT", paths["dashboard"].read_text())
            self.assertIn("SPK", paths["report_markdown"].read_text())
            self.assertTrue(paths["database"].exists())
            self.assertTrue(paths["crosswalk"].exists())
            self.assertTrue(paths["applicability"].exists())
            self.assertTrue(paths["audit_bundle"].exists())
            evidence = EvidenceManifest.from_dict(
                json.loads(paths["evidence_manifest"].read_text())
            )
            self.assertEqual(evidence.verify(), (True, ()))
            self.assertTrue(verify_audit_bundle(paths["audit_bundle"]).valid)
            valid, errors = AuditChain.read(paths["audit"]).verify()
        self.assertTrue(valid, errors)


if __name__ == "__main__":
    unittest.main()
