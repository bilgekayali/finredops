from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from finredops.audit import AuditChain
from finredops.models import sha256_digest

from tests.helpers import NOW


class AuditTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
