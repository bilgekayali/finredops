from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from finredops.audit import AuditChain
from finredops.demo import build_demo_service
from finredops.store import PersistenceConflict, SQLiteGovernanceStore

from tests.helpers import NOW


class StoreTests(unittest.TestCase):
    def test_snapshot_revisions_are_idempotent_and_loadable(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        with SQLiteGovernanceStore(":memory:") as store:
            first = store.save_snapshot(snapshot, now=NOW)
            duplicate = store.save_snapshot(snapshot, now=NOW)
            changed = {**snapshot, "simulation_only": False}
            second = store.save_snapshot(changed, now=NOW)
            self.assertEqual(first.revision, duplicate.revision)
            self.assertEqual(second.revision, 2)
            self.assertFalse(store.load_latest(engagement_id)["simulation_only"])

    def test_audit_chain_persists_and_verifies(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        with SQLiteGovernanceStore(":memory:") as store:
            inserted = store.persist_audit_chain(engagement_id, service.audit)
            self.assertEqual(inserted, len(service.audit.events))
            self.assertEqual(store.persist_audit_chain(engagement_id, service.audit), 0)
            self.assertEqual(store.verify_persisted_audit(engagement_id), (True, ()))

    def test_divergent_audit_prefix_is_rejected(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        divergent = AuditChain()
        divergent.append(
            timestamp=NOW,
            actor_id="different",
            event_type="engagement.registered",
            engagement_id=engagement_id,
            payload={"different": True},
        )
        with SQLiteGovernanceStore(":memory:") as store:
            store.persist_audit_chain(engagement_id, service.audit)
            with self.assertRaises(PersistenceConflict):
                store.persist_audit_chain(engagement_id, divergent)

    def test_idempotency_key_cannot_be_reused_for_different_content(self) -> None:
        with SQLiteGovernanceStore(":memory:") as store:
            key = "request-00000001"
            self.assertTrue(
                store.record_idempotency(key, request={"a": 1}, result={"ok": True}, now=NOW)
            )
            self.assertFalse(
                store.record_idempotency(key, request={"a": 1}, result={"ok": True}, now=NOW)
            )
            with self.assertRaises(PersistenceConflict):
                store.record_idempotency(
                    key, request={"a": 2}, result={"ok": True}, now=NOW
                )

    def test_file_database_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with SQLiteGovernanceStore(path):
                pass
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
