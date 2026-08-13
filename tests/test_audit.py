from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finredops.anchor_models import (
    AuditAnchorCommitment,
    AuditAnchorTrustBundle,
    AuditAnchorTrustKey,
    b64url,
)
from finredops.anchor_verify import verify_audit_anchor_chain, verify_audit_anchor_receipt
from finredops.audit import AuditChain
from finredops.models import sha256_digest
from finredops.reference_anchor import ReferenceAppendOnlyAnchorAuthority

from tests.helpers import NOW


class AuditTests(unittest.TestCase):
    def _anchor_commitment(
        self, engagement_id: str = "ENG-ANCHOR-1", institution_id: str = "bank-a"
    ) -> AuditAnchorCommitment:
        item = AuditAnchorCommitment(
            institution_id=institution_id,
            engagement_id=engagement_id,
            event_count=2,
            head_event_hash="1" * 64,
            audit_document_digest="2" * 64,
            audit_target_digest="3" * 64,
            audit_signature_artifact_digest="4" * 64,
            source_artifact_digest="5" * 64,
        )
        return AuditAnchorCommitment(**item.core(), commitment_digest=item.digest())

    def _anchor_trust(
        self, private_key: Ed25519PrivateKey, *, status: str = "active"
    ) -> AuditAnchorTrustBundle:
        key = AuditAnchorTrustKey(
            key_id="anchor-key-1",
            public_key=b64url(private_key.public_key().public_bytes_raw()),
            not_before=NOW - timedelta(hours=1),
            not_after=NOW + timedelta(hours=1),
            status=status,
        )
        bundle = AuditAnchorTrustBundle(anchor_id="anchor-primary", keys=(key,))
        return AuditAnchorTrustBundle(
            anchor_id=bundle.anchor_id,
            keys=bundle.keys,
            bundle_digest=bundle.digest(),
        )

    def test_round_trip_and_verify(self) -> None:
        chain = AuditChain()
        chain.append(
            timestamp=NOW,
            actor_id="tester",
            event_type="test.started",
            engagement_id="ENG-1",
            payload={"synthetic": True},
        )
        chain.append(
            timestamp=NOW,
            actor_id="tester",
            event_type="test.finished",
            engagement_id="ENG-1",
            payload={"result": "pass"},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            chain.write(path)
            loaded = AuditChain.read(path)
        self.assertEqual(loaded.verify(), (True, ()))

    def test_modified_event_breaks_chain(self) -> None:
        chain = AuditChain()
        event = chain.append(
            timestamp=NOW,
            actor_id="tester",
            event_type="test.event",
            engagement_id="ENG-1",
            payload={"decision": "allowed"},
        )
        altered = replace(event, payload={"decision": "denied"})
        valid, errors = AuditChain((altered,)).verify()
        self.assertFalse(valid)
        self.assertIn("event hash mismatch", errors[0])

    def test_backwards_timestamp_is_rejected_even_with_valid_hashes(self) -> None:
        chain = AuditChain()
        first = chain.append(
            timestamp=NOW,
            actor_id="tester",
            event_type="test.first",
            engagement_id="ENG-1",
            payload={},
        )
        second = chain.append(
            timestamp=NOW + timedelta(seconds=1),
            actor_id="tester",
            event_type="test.second",
            engagement_id="ENG-1",
            payload={},
        )
        altered = replace(second, timestamp=NOW - timedelta(seconds=1))
        altered = replace(altered, event_hash=sha256_digest(altered.hash_payload()))
        valid, errors = AuditChain((first, altered)).verify()
        self.assertFalse(valid)
        self.assertIn("timestamp moves backwards", " ".join(errors))

    def test_external_anchor_receipt_verifies_with_independent_trust(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        item = self._anchor_commitment()
        with tempfile.TemporaryDirectory() as directory:
            authority = ReferenceAppendOnlyAnchorAuthority(
                Path(directory) / "anchor.db",
                anchor_id="anchor-primary",
                key_id="anchor-key-1",
                private_key=private_key,
                clock=lambda: NOW,
            )
            receipt = authority.append(item)
        self.assertTrue(
            verify_audit_anchor_receipt(
                item,
                receipt,
                trust_bundle=self._anchor_trust(private_key),
                expected_sequence=1,
                expected_previous_receipt_digest="0" * 64,
            )
        )

    def test_external_anchor_chain_rejects_reorder_and_cross_institution(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        first = self._anchor_commitment()
        second = self._anchor_commitment("ENG-ANCHOR-2")
        with tempfile.TemporaryDirectory() as directory:
            authority = ReferenceAppendOnlyAnchorAuthority(
                Path(directory) / "anchor.db",
                anchor_id="anchor-primary",
                key_id="anchor-key-1",
                private_key=private_key,
                clock=lambda: NOW,
            )
            one = authority.append(first)
            same = authority.append(first)
            two = authority.append(second)
        self.assertEqual(one.digest(), same.digest())
        self.assertEqual(two.previous_receipt_digest, one.digest())
        self.assertFalse(
            verify_audit_anchor_chain((two, one), trust_bundle=self._anchor_trust(private_key))[0]
        )
        other = self._anchor_commitment(institution_id="bank-b")
        self.assertFalse(
            verify_audit_anchor_receipt(
                other, one, trust_bundle=self._anchor_trust(private_key)
            )
        )

    def test_external_anchor_disabled_key_and_backwards_authority_time_fail_closed(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        item = self._anchor_commitment()
        times = iter((NOW, NOW - timedelta(seconds=1)))
        with tempfile.TemporaryDirectory() as directory:
            authority = ReferenceAppendOnlyAnchorAuthority(
                Path(directory) / "anchor.db",
                anchor_id="anchor-primary",
                key_id="anchor-key-1",
                private_key=private_key,
                clock=lambda: next(times),
            )
            receipt = authority.append(item)
            with self.assertRaises(ValueError):
                authority.append(self._anchor_commitment("ENG-ANCHOR-2"))
        self.assertFalse(
            verify_audit_anchor_receipt(
                item,
                receipt,
                trust_bundle=self._anchor_trust(private_key, status="disabled"),
            )
        )


if __name__ == "__main__":
    unittest.main()