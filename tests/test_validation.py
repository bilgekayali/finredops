from __future__ import annotations

import ssl
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from finredops.models import Environment, ExecutionStatus
from finredops.validation import (
    BoundedTlsHeadTransport,
    ControlledValidationRunner,
    ProbeFailure,
    ProbeResponse,
    receipt_to_security_findings,
)

from tests.helpers import NOW, make_engagement, make_proposal


class FakeTransport:
    def __init__(self, response: ProbeResponse | None = None) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def head(
        self,
        *,
        target: str,
        port: int,
        path: str,
        timeout_seconds: int,
    ) -> ProbeResponse:
        self.calls.append(
            {
                "target": target,
                "port": port,
                "path": path,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.response is None:
            raise ProbeFailure("PROBE_TIMEOUT", "The bounded validation request timed out.")
        return self.response


def insecure_response() -> ProbeResponse:
    return ProbeResponse(
        status_code=302,
        headers=(
            ("location", "https://identity.example.test/login?state=sensitive"),
            ("set-cookie", "session=do-not-store-this-value; Path=/"),
            ("server", "example"),
        ),
        tls_version="TLSv1.3",
        certificate_not_after=NOW + timedelta(days=10),
        peer_address="192.0.2.10",
    )


class ControlledValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engagement = make_engagement()
        self.proposal = make_proposal(
            self.engagement,
            action_id="http.security_posture.validate",
            parameters={
                "change_reference": "CHG-SYNTH-001",
                "port": 443,
                "path": "/",
                "timeout_seconds": 3,
            },
        )

    def test_bounded_probe_produces_sanitized_review_findings(self) -> None:
        transport = FakeTransport(insecure_response())
        receipt = ControlledValidationRunner(transport).execute(
            self.proposal, self.engagement, now=NOW
        )
        self.assertEqual(receipt.status, ExecutionStatus.VALIDATED)
        self.assertEqual(len(transport.calls), 1)
        self.assertTrue(receipt.evidence["active_validation"])
        self.assertFalse(receipt.evidence["response_body_collected"])
        self.assertFalse(receipt.evidence["redirect_followed"])
        self.assertEqual(receipt.evidence["request"]["method"], "HEAD")
        document = str(receipt.evidence)
        self.assertNotIn("do-not-store-this-value", document)
        self.assertNotIn("state=sensitive", document)
        rule_ids = {item["rule_id"] for item in receipt.evidence["findings"]}
        self.assertEqual(
            rule_ids,
            {
                "HTTP-HSTS-001",
                "HTTP-CSP-001",
                "HTTP-NOSNIFF-001",
                "HTTP-COOKIE-001",
                "TLS-CERT-EXPIRY-001",
            },
        )
        report_findings = receipt_to_security_findings(receipt)
        self.assertEqual(len(report_findings), len(rule_ids))
        self.assertTrue(all(item.evidence_refs for item in report_findings))

    def test_secure_response_can_complete_without_findings(self) -> None:
        response = ProbeResponse(
            status_code=200,
            headers=(
                ("strict-transport-security", "max-age=31536000"),
                ("content-security-policy", "default-src 'self'"),
                ("x-content-type-options", "nosniff"),
                ("set-cookie", "id=value; Secure; HttpOnly; SameSite=Strict"),
            ),
            tls_version="TLSv1.3",
            certificate_not_after=NOW + timedelta(days=90),
            peer_address="192.0.2.10",
        )
        receipt = ControlledValidationRunner(FakeTransport(response)).execute(
            self.proposal, self.engagement, now=NOW
        )
        self.assertEqual(receipt.status, ExecutionStatus.VALIDATED)
        self.assertEqual(receipt.evidence["findings"], ())

    def test_operational_failure_is_not_misreported_as_a_finding(self) -> None:
        receipt = ControlledValidationRunner(FakeTransport()).execute(
            self.proposal, self.engagement, now=NOW
        )
        self.assertEqual(receipt.status, ExecutionStatus.FAILED)
        self.assertEqual(receipt.evidence["error_code"], "PROBE_TIMEOUT")
        self.assertEqual(receipt.evidence["findings"], ())
        self.assertEqual(receipt_to_security_findings(receipt), ())

    def test_unsupported_head_method_is_not_misreported_as_a_finding(self) -> None:
        response = replace(insecure_response(), status_code=405)
        receipt = ControlledValidationRunner(FakeTransport(response)).execute(
            self.proposal, self.engagement, now=NOW
        )
        self.assertEqual(receipt.status, ExecutionStatus.FAILED)
        self.assertEqual(receipt.evidence["error_code"], "HTTP_HEAD_UNSUPPORTED")
        self.assertEqual(receipt.evidence["findings"], ())

    def test_production_and_unsafe_parameters_are_refused(self) -> None:
        production = replace(
            self.engagement,
            assets=(replace(self.engagement.assets[0], environment=Environment.PRODUCTION),),
        )
        with self.assertRaises(PermissionError):
            ControlledValidationRunner(FakeTransport(insecure_response())).execute(
                self.proposal, production, now=NOW
            )
        traversal = replace(self.proposal, parameters={"change_reference": "CHG-1", "path": "/../admin"})
        with self.assertRaises(ValueError):
            ControlledValidationRunner(FakeTransport(insecure_response())).execute(
                traversal, self.engagement, now=NOW
            )

    def test_kill_switch_cancels_before_network_activity(self) -> None:
        transport = FakeTransport(insecure_response())
        receipt = ControlledValidationRunner(transport).execute(
            self.proposal,
            self.engagement,
            now=NOW,
            is_cancelled=lambda: True,
        )
        self.assertEqual(receipt.status, ExecutionStatus.CANCELLED)
        self.assertEqual(transport.calls, [])
        self.assertFalse(receipt.evidence["network_activity"])

    def test_transport_parser_preserves_duplicate_headers_without_a_body(self) -> None:
        transport = BoundedTlsHeadTransport()
        status, headers = transport._parse_headers(  # noqa: SLF001 - boundary unit test
            b"HTTP/1.1 200 OK\r\nSet-Cookie: one=value\r\nSet-Cookie: two=value"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(headers), 2)
        with self.assertRaises(ProbeFailure):
            transport._parse_headers(  # noqa: SLF001 - boundary unit test
                b"HTTP/1.1 200 OK\r\n folded: value"
            )

    def test_transport_denies_loopback_resolution(self) -> None:
        transport = BoundedTlsHeadTransport()
        records = [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("finredops.validation.socket.getaddrinfo", return_value=records):
            with self.assertRaises(ProbeFailure) as caught:
                transport._resolve_once("approved.example.test", 443)  # noqa: SLF001
        self.assertEqual(caught.exception.code, "RESOLVED_ADDRESS_DENIED")

    def test_transport_refuses_an_unverified_tls_context(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError):
            BoundedTlsHeadTransport(context)


if __name__ == "__main__":
    unittest.main()
