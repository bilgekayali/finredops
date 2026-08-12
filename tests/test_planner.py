from __future__ import annotations

import unittest

from finredops.planner import GuardedPlanningGateway, PlanValidationError, synthetic_plan_document

from tests.helpers import NOW, make_engagement


class PlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = GuardedPlanningGateway()
        self.engagement = make_engagement()

    def test_known_structured_plan_is_imported(self) -> None:
        proposals = self.gateway.parse(
            synthetic_plan_document(),
            engagement=self.engagement,
            proposed_by="ai-planner",
            now=NOW,
        )
        self.assertEqual(len(proposals), 4)
        self.assertTrue(all(item.proposed_by == "ai-planner" for item in proposals))

    def test_unknown_action_is_rejected(self) -> None:
        plan = synthetic_plan_document()
        plan["proposals"][0]["action_id"] = "shell.execute"
        with self.assertRaisesRegex(PlanValidationError, "unknown catalog action"):
            self.gateway.parse(
                plan, engagement=self.engagement, proposed_by="ai-planner", now=NOW
            )

    def test_command_field_is_rejected(self) -> None:
        plan = synthetic_plan_document()
        plan["proposals"][0]["command"] = "not accepted"
        with self.assertRaisesRegex(PlanValidationError, "unknown command"):
            self.gateway.parse(
                plan, engagement=self.engagement, proposed_by="ai-planner", now=NOW
            )

    def test_nested_parameters_are_rejected(self) -> None:
        plan = synthetic_plan_document()
        plan["proposals"][0]["parameters"] = {"expected_control": {"nested": True}}
        with self.assertRaisesRegex(PlanValidationError, "scalar values only"):
            self.gateway.parse(
                plan, engagement=self.engagement, proposed_by="ai-planner", now=NOW
            )


if __name__ == "__main__":
    unittest.main()
