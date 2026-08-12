from __future__ import annotations

import unittest

from finredops.dashboard import render_dashboard
from finredops.demo import build_demo_service

from tests.helpers import NOW


class DashboardTests(unittest.TestCase):
    def test_dashboard_contains_operational_states(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        document = render_dashboard(service.snapshot(engagement_id))
        self.assertIn("FinRedOps", document)
        self.assertIn("SIMULATED", document)
        self.assertIn("DENIED", document)
        self.assertIn("Tamper-evident audit trail", document)
        self.assertIn("TS 13638/T2", document)
        self.assertIn("v0.4", document)

    def test_dashboard_escapes_snapshot_values(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        snapshot["engagement"]["name"] = "<script>alert(1)</script>"
        document = render_dashboard(snapshot)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn("&lt;script&gt;", document)


if __name__ == "__main__":
    unittest.main()
