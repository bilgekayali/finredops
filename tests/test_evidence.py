from __future__ import annotations

import unittest

from finredops.evidence import DataFindingKind, EvidenceGuard
from finredops.models import canonical_json


class EvidenceGuardTests(unittest.TestCase):
    def test_sensitive_identifiers_and_secret_fields_are_redacted(self) -> None:
        evidence = {
            "api_key": "never-store-this-value",
            "note": (
                "mail user@example.com card 4111 1111 1111 1111 "
                "iban TR330006100519786457841326"
            ),
            "authorization_line": "Bearer abcdefghijklmnop",
        }
        result = EvidenceGuard().sanitize(evidence)
        serialized = canonical_json(result.evidence)
        for secret in (
            "never-store-this-value",
            "user@example.com",
            "4111 1111 1111 1111",
            "TR330006100519786457841326",
            "abcdefghijklmnop",
        ):
            self.assertNotIn(secret, serialized)
        kinds = {finding.kind for finding in result.findings}
        self.assertTrue(
            {
                DataFindingKind.SECRET_FIELD,
                DataFindingKind.EMAIL,
                DataFindingKind.PAYMENT_CARD,
                DataFindingKind.IBAN,
                DataFindingKind.BEARER_TOKEN,
            }.issubset(kinds)
        )

    def test_invalid_card_and_iban_are_not_false_positive_matches(self) -> None:
        evidence = {"note": "card 4111111111111112 iban TR000000000000000000000000"}
        result = EvidenceGuard().sanitize(evidence)
        self.assertFalse(result.redacted)
        self.assertEqual(result.evidence["note"], evidence["note"])

    def test_redaction_is_deterministic(self) -> None:
        guard = EvidenceGuard()
        first = guard.sanitize({"email": "person@example.test"})
        second = guard.sanitize({"email": "person@example.test"})
        self.assertEqual(first.sanitized_digest, second.sanitized_digest)
        self.assertEqual(first.findings, second.findings)


if __name__ == "__main__":
    unittest.main()
