from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from finredops.audit import AuditChain
from finredops.demo import build_demo_service
from finredops.models import canonical_json, sha256_digest
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
            self.assertEqual(first.institution_id, "default")
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

    def test_same_identifiers_are_isolated_between_institutions(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        changed = {**snapshot, "simulation_only": False}
        key = "shared-request-0001"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with SQLiteGovernanceStore(path, institution_id="bank-a") as bank_a:
                bank_a.save_snapshot(snapshot, now=NOW)
                bank_a.persist_audit_chain(engagement_id, service.audit)
                self.assertTrue(
                    bank_a.record_idempotency(
                        key, request={"tenant": "a"}, result={"ok": True}, now=NOW
                    )
                )
            with SQLiteGovernanceStore(path, institution_id="bank-b") as bank_b:
                bank_b.save_snapshot(changed, now=NOW)
                bank_b.persist_audit_chain(engagement_id, service.audit)
                self.assertTrue(
                    bank_b.record_idempotency(
                        key, request={"tenant": "b"}, result={"ok": True}, now=NOW
                    )
                )
            with SQLiteGovernanceStore(path, institution_id="bank-a") as bank_a:
                self.assertTrue(bank_a.load_latest(engagement_id)["simulation_only"])
                self.assertEqual(bank_a.verify_persisted_audit(engagement_id), (True, ()))
                self.assertEqual(bank_a.metadata()["institution_id"], "bank-a")
            with SQLiteGovernanceStore(path, institution_id="bank-b") as bank_b:
                self.assertFalse(bank_b.load_latest(engagement_id)["simulation_only"])
                self.assertEqual(bank_b.verify_persisted_audit(engagement_id), (True, ()))
                self.assertEqual(bank_b.metadata()["institution_id"], "bank-b")

    def test_v1_database_migrates_into_default_institution(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        document = canonical_json(snapshot)
        digest = sha256_digest(snapshot)
        created_at = NOW.isoformat().replace("+00:00", "Z")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE engagement_snapshots (
                    engagement_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    snapshot_json TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (engagement_id, revision),
                    UNIQUE (engagement_id, snapshot_digest)
                );
                CREATE TABLE audit_events (
                    engagement_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
                    previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                    PRIMARY KEY (engagement_id, sequence),
                    UNIQUE (engagement_id, event_hash)
                );
                CREATE TABLE idempotency_records (
                    idempotency_key TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX idx_snapshot_latest
                    ON engagement_snapshots (engagement_id, revision DESC);
                PRAGMA user_version = 1;
                """
            )
            connection.execute(
                """
                INSERT INTO engagement_snapshots
                    (engagement_id, revision, snapshot_json, snapshot_digest, created_at)
                VALUES (?, 1, ?, ?, ?)
                """,
                (engagement_id, document, digest, created_at),
            )
            connection.commit()
            connection.close()

            with SQLiteGovernanceStore(path) as store:
                self.assertEqual(store.metadata()["schema_version"], 3)
                self.assertEqual(store.load_latest(engagement_id), snapshot)
            with SQLiteGovernanceStore(path, institution_id="bank-other") as store:
                self.assertIsNone(store.load_latest(engagement_id))

    def test_file_database_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with SQLiteGovernanceStore(path):
                pass
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
