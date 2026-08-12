from __future__ import annotations

import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from finredops.api import create_read_only_server
from finredops.demo import build_demo_assurance_snapshot, build_demo_service

from tests.helpers import NOW


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot, _, _, _ = build_demo_assurance_snapshot(
            service, engagement_id, now=NOW
        )
        self.server = create_read_only_server(
            snapshot, host="127.0.0.1", port=0
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_health_is_read_only_and_security_hardened(self) -> None:
        with urlopen(self.base + "/api/v1/health", timeout=2) as response:
            body = json.load(response)
            self.assertEqual(body["mode"], "synthetic_simulation_only")
            self.assertFalse(body["write_operations"])
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])

    def test_mutation_method_is_rejected(self) -> None:
        request = Request(self.base + "/api/v1/engagement", data=b"{}", method="POST")
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)
        self.assertEqual(caught.exception.code, 405)
        self.assertEqual(caught.exception.headers["Allow"], "GET, HEAD")

    def test_dashboard_etag_is_stable(self) -> None:
        with urlopen(self.base + "/", timeout=2) as response:
            self.assertTrue(response.headers["ETag"])
            self.assertIn(b"ASSURANCE CONTROL PLANE", response.read())

    def test_regulatory_profile_and_report_capabilities_are_exposed(self) -> None:
        with urlopen(self.base + "/api/v1/regulatory/profile", timeout=2) as response:
            profile = json.load(response)
        with urlopen(self.base + "/api/v1/reporting/capabilities", timeout=2) as response:
            capabilities = json.load(response)
        self.assertEqual(profile["profile_id"], "turkey-financial-assurance-v1")
        self.assertIn("annual_bank_penetration", capabilities["report_types"])
        self.assertTrue(capabilities["human_issue_approval_required"])
        self.assertTrue(capabilities["report_delta_supported"])

    def test_execution_capabilities_are_read_only_and_default_safe(self) -> None:
        with urlopen(self.base + "/api/v1/execution/capabilities", timeout=2) as response:
            capabilities = json.load(response)
        self.assertEqual(capabilities["default_mode"], "simulation")
        self.assertFalse(capabilities["controlled_validation"])
        self.assertFalse(capabilities["network_enablement_via_read_only_api"])

    def test_applicability_and_evidence_metadata_are_exposed(self) -> None:
        with urlopen(self.base + "/api/v1/regulatory/applicability", timeout=2) as response:
            applicability = json.load(response)
        with urlopen(self.base + "/api/v1/evidence/manifest", timeout=2) as response:
            evidence = json.load(response)
        self.assertTrue(applicability["ready_for_audit"])
        self.assertTrue(
            any(item["authority"] == "TSE" for item in applicability["decisions"])
        )
        self.assertTrue(evidence["valid"])
        self.assertFalse(evidence["raw_evidence_embedded"])

    def test_unknown_route_returns_json_404(self) -> None:
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.base + "/does-not-exist", timeout=2)
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(json.load(caught.exception)["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
