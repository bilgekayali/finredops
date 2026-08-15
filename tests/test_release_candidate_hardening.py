from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finredops.demo import build_demo_service
from finredops.evidence_vault import EvidenceVault
from finredops.models import DataClassification
from finredops.reference_anchor import ReferenceAppendOnlyAnchorAuthority
from finredops.release_compatibility import PERSISTENCE_COMPATIBILITY, release_compatibility_manifest
from finredops.store import SQLiteGovernanceStore
from finredops.vault_common import EvidenceVaultError
from finredops.vault_store import SQLiteEvidenceVaultBackend
from finredops.workload_ledger import SQLiteOneTimeGrantLedger, WorkloadLedgerError

from tests.helpers import NOW
from tests.test_kms_envelope import MemoryInstitutionProvider, institution_context


class ReleaseCandidateHardeningTests(unittest.TestCase):
    def test_release_manifest_declares_fail_closed_schema_policy(self) -> None:
        manifest = release_compatibility_manifest()
        self.assertEqual(manifest["release_version"], "0.9.3")
        self.assertFalse(manifest["automatic_downgrade_supported"])
        self.assertFalse(manifest["unknown_future_schema_open_supported"])
        self.assertTrue(manifest["backup_before_migration_required"])
        by_name = {item.name: item for item in PERSISTENCE_COMPATIBILITY}
        self.assertEqual(by_name["sqlite-governance-store"].classify(1), "upgradeable")
        self.assertEqual(by_name["sqlite-governance-store"].classify(2), "upgradeable")
        self.assertEqual(by_name["sqlite-governance-store"].classify(3), "current")
        self.assertEqual(by_name["sqlite-governance-store"].classify(4), "future_unsupported")

    def test_v2_governance_database_migrates_to_v3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v2.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE engagement_snapshots (
                    institution_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (institution_id, engagement_id, revision),
                    UNIQUE (institution_id, engagement_id, snapshot_digest)
                );
                CREATE TABLE audit_events (
                    institution_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    PRIMARY KEY (institution_id, engagement_id, sequence),
                    UNIQUE (institution_id, engagement_id, event_hash)
                );
                CREATE TABLE idempotency_records (
                    institution_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (institution_id, idempotency_key)
                );
                CREATE INDEX idx_snapshot_latest
                    ON engagement_snapshots (institution_id, engagement_id, revision DESC);
                PRAGMA user_version = 2;
                """
            )
            connection.close()
            with SQLiteGovernanceStore(path, institution_id="bank-a") as store:
                self.assertEqual(store.metadata()["schema_version"], 3)
            connection = sqlite3.connect(path)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(engagement_snapshots)")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.close()
            self.assertEqual(version, 3)
            self.assertIn("protection_mode", columns)
            self.assertIn("protection_key_id", columns)

    def test_future_sqlite_schemas_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("governance.sqlite", "vault.sqlite", "ledger.sqlite", "anchor.sqlite"):
                connection = sqlite3.connect(root / name)
                connection.execute("PRAGMA user_version = 99")
                connection.commit()
                connection.close()
            with self.assertRaises(RuntimeError):
                SQLiteGovernanceStore(root / "governance.sqlite")
            with self.assertRaises(EvidenceVaultError):
                SQLiteEvidenceVaultBackend(root / "vault.sqlite", institution_id="bank-a")
            with self.assertRaises(WorkloadLedgerError):
                SQLiteOneTimeGrantLedger(root / "ledger.sqlite")
            with self.assertRaises(RuntimeError):
                ReferenceAppendOnlyAnchorAuthority(
                    root / "anchor.sqlite",
                    anchor_id="anchor-a",
                    key_id="anchor-key-a",
                    private_key=Ed25519PrivateKey.generate(),
                )

    def test_governance_snapshot_failure_rolls_back_entire_transaction(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        with SQLiteGovernanceStore(":memory:") as store:
            with patch.object(store, "_protect_document", side_effect=RuntimeError("injected failure")):
                with self.assertRaises(RuntimeError):
                    store.save_snapshot(snapshot, now=NOW)
            self.assertIsNone(store.load_latest(engagement_id))
            saved = store.save_snapshot(snapshot, now=NOW)
            self.assertEqual(saved.revision, 1)

    def test_vault_create_failure_rolls_back_record_and_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.sqlite"
            provider = MemoryInstitutionProvider()
            backend = SQLiteEvidenceVaultBackend(path, institution_id="bank-a")
            vault = EvidenceVault(
                institution_context=institution_context("bank-a"),
                provider=provider,
                backend=backend,
            )
            with patch.object(backend, "_insert_event", side_effect=RuntimeError("injected failure")):
                with self.assertRaises(RuntimeError):
                    vault.ingest(
                        b"synthetic rollback evidence",
                        engagement_id="ENG-RC-001",
                        evidence_id="EV-RC-001",
                        title="Rollback test",
                        classification=DataClassification.RESTRICTED,
                        media_type="text/plain",
                        source_system="test-lab",
                        collected_by="tester",
                        collected_at=NOW,
                        retention_until=(NOW + timedelta(days=30)).date(),
                        actor_id="tester",
                        now=NOW + timedelta(minutes=1),
                    )
            self.assertEqual(backend.metadata()["record_count"], 0)
            with self.assertRaises(EvidenceVaultError):
                backend.load_record("EV-RC-001")
            backend.close()

    def test_closed_file_backup_restores_governance_and_encrypted_vault(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service, engagement_id = build_demo_service(now=NOW)
            snapshot = service.snapshot(engagement_id)
            source_governance = root / "governance.sqlite"
            backup_governance = root / "governance.backup.sqlite"
            with SQLiteGovernanceStore(source_governance, institution_id="bank-a") as store:
                store.save_snapshot(snapshot, now=NOW)
                store.persist_audit_chain(engagement_id, service.audit)
            shutil.copy2(source_governance, backup_governance)
            with SQLiteGovernanceStore(backup_governance, institution_id="bank-a") as restored:
                self.assertEqual(restored.load_latest(engagement_id), snapshot)
                self.assertEqual(restored.verify_persisted_audit(engagement_id), (True, ()))

            provider = MemoryInstitutionProvider()
            source_vault = root / "vault.sqlite"
            backup_vault = root / "vault.backup.sqlite"
            backend = SQLiteEvidenceVaultBackend(source_vault, institution_id="bank-a")
            vault = EvidenceVault(
                institution_context=institution_context("bank-a"),
                provider=provider,
                backend=backend,
            )
            raw = b"encrypted backup evidence"
            vault.ingest(
                raw,
                engagement_id="ENG-RC-002",
                evidence_id="EV-RC-002",
                title="Encrypted backup",
                classification=DataClassification.RESTRICTED,
                media_type="text/plain",
                source_system="test-lab",
                collected_by="tester",
                collected_at=NOW,
                retention_until=(NOW + timedelta(days=30)).date(),
                actor_id="tester",
                now=NOW + timedelta(minutes=1),
            )
            backend.close()
            shutil.copy2(source_vault, backup_vault)
            restored_backend = SQLiteEvidenceVaultBackend(backup_vault, institution_id="bank-a")
            restored_vault = EvidenceVault(
                institution_context=institution_context("bank-a"),
                provider=provider,
                backend=restored_backend,
            )
            self.assertEqual(
                restored_vault.access(
                    "EV-RC-002",
                    actor_id="recovery-tester",
                    purpose="Validate closed-file backup recovery.",
                    now=NOW + timedelta(minutes=2),
                ),
                raw,
            )
            restored_backend.close()


if __name__ == "__main__":
    unittest.main()
