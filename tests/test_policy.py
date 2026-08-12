from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from finredops.models import ApprovalDecision, EngagementStatus, Role
from finredops.policy import PolicyEngine

from tests.helpers import (
    NOW,
    controlled_proposal_approvals,
    make_approval,
    make_engagement,
    make_proposal,
    proposal_approvals,
)


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyEngine()
        self.engagement = make_engagement()
        self.proposal = make_proposal(self.engagement)

    def test_all_mandatory_controls_allow_safe_proposal(self) -> None:
        decision = self.policy.evaluate(
            self.engagement,
            self.proposal,
            proposal_approvals(self.proposal),
            now=NOW,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, "POLICY_ALLOW")

    def test_scope_exclusion_wins(self) -> None:
        proposal = make_proposal(self.engagement, target="excluded.example.test")
        decision = self.policy.evaluate(
            self.engagement, proposal, proposal_approvals(proposal), now=NOW
        )
        self.assertFalse(decision.allowed)
        self.assertIn("explicitly excluded", " ".join(decision.reasons))

    def test_stale_approvals_do_not_authorize_changed_proposal(self) -> None:
        approvals = proposal_approvals(self.proposal)
        changed = replace(self.proposal, rationale="A materially changed synthetic rationale.")
        decision = self.policy.evaluate(self.engagement, changed, approvals, now=NOW)
        self.assertFalse(decision.allowed)
        self.assertIn("Missing proposal approval roles", " ".join(decision.reasons))

    def test_controlled_action_is_denied_even_with_approvals(self) -> None:
        proposal = make_proposal(
            self.engagement,
            action_id="vulnerability.validation.controlled",
            parameters={"finding_reference": "SYNTH-FINDING"},
        )
        decision = self.policy.evaluate(
            self.engagement, proposal, proposal_approvals(proposal), now=NOW
        )
        self.assertFalse(decision.allowed)
        self.assertIn("no approved v0.4 runner", " ".join(decision.reasons))

    def test_bounded_controlled_action_requires_runner_and_three_roles(self) -> None:
        proposal = make_proposal(
            self.engagement,
            action_id="http.security_posture.validate",
            parameters={"change_reference": "CHG-SYNTH-001"},
        )
        without_owner = self.policy.evaluate(
            self.engagement,
            proposal,
            proposal_approvals(proposal),
            now=NOW,
            controlled_runner_available=True,
        )
        self.assertFalse(without_owner.allowed)
        self.assertIn("business_owner", " ".join(without_owner.reasons))

        allowed = self.policy.evaluate(
            self.engagement,
            proposal,
            controlled_proposal_approvals(proposal),
            now=NOW,
            controlled_runner_available=True,
        )
        self.assertTrue(allowed.allowed, allowed.reasons)

    def test_controlled_action_rate_limit_and_parameters_fail_closed(self) -> None:
        invalid = make_proposal(
            self.engagement,
            action_id="http.security_posture.validate",
            parameters={"change_reference": "CHG-1", "path": "/../../admin"},
        )
        invalid_decision = self.policy.evaluate(
            self.engagement,
            invalid,
            controlled_proposal_approvals(invalid),
            now=NOW,
            controlled_runner_available=True,
        )
        self.assertFalse(invalid_decision.allowed)
        self.assertIn("Invalid controlled-validation", " ".join(invalid_decision.reasons))

        proposal = make_proposal(
            self.engagement,
            action_id="http.security_posture.validate",
            parameters={"change_reference": "CHG-2"},
        )
        limited = self.policy.evaluate(
            self.engagement,
            proposal,
            controlled_proposal_approvals(proposal),
            now=NOW,
            controlled_runner_available=True,
            requests_in_last_minute=self.engagement.max_requests_per_minute,
        )
        self.assertFalse(limited.allowed)
        self.assertIn("rate ceiling", " ".join(limited.reasons))

    def test_command_bearing_parameter_is_denied(self) -> None:
        proposal = make_proposal(self.engagement, parameters={"shell": "anything"})
        decision = self.policy.evaluate(
            self.engagement, proposal, proposal_approvals(proposal), now=NOW
        )
        self.assertFalse(decision.allowed)
        self.assertIn("Forbidden command", " ".join(decision.reasons))

    def test_distinct_actors_are_required(self) -> None:
        approvals = (
            make_approval(self.proposal, actor_id="same", role=Role.CONTROL_TEAM),
            make_approval(self.proposal, actor_id="same", role=Role.EXECUTION_APPROVER),
        )
        decision = self.policy.evaluate(self.engagement, self.proposal, approvals, now=NOW)
        self.assertFalse(decision.allowed)
        self.assertIn("distinct actors", " ".join(decision.reasons))

    def test_denial_and_emergency_stop_fail_closed(self) -> None:
        approvals = (*proposal_approvals(self.proposal), make_approval(
            self.proposal,
            actor_id="risk",
            role=Role.CONTROL_TEAM,
            decision=ApprovalDecision.DENIED,
            approval_id="APR-DENY",
        ))
        decision = self.policy.evaluate(
            self.engagement, self.proposal, approvals, now=NOW, emergency_stop=True
        )
        self.assertFalse(decision.allowed)
        joined = " ".join(decision.reasons)
        self.assertIn("Emergency stop", joined)
        self.assertIn("denial exists", joined)

    def test_engagement_requires_owner_and_control_approval(self) -> None:
        pending = make_engagement(status=EngagementStatus.PENDING_APPROVAL)
        approvals = (
            make_approval(pending, actor_id="owner", role=Role.BUSINESS_OWNER),
            make_approval(pending, actor_id="control", role=Role.CONTROL_TEAM),
        )
        ready, reasons = self.policy.engagement_approval_ready(pending, approvals, now=NOW)
        self.assertTrue(ready, reasons)

    def test_approval_exceeding_engagement_ttl_is_rejected(self) -> None:
        approvals = list(proposal_approvals(self.proposal))
        approvals[0] = replace(
            approvals[0], expires_at=approvals[0].decided_at + timedelta(hours=3)
        )
        decision = self.policy.evaluate(self.engagement, self.proposal, approvals, now=NOW)
        self.assertFalse(decision.allowed)
        self.assertIn("exceeds the configured approval TTL", " ".join(decision.reasons))


if __name__ == "__main__":
    unittest.main()
