from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from finredops.evidence_vault import EvidenceVault
from finredops.models import DataClassification
from finredops.vault_common import EvidenceVaultError
from finredops.vault_store import SQLiteEvidenceVaultBackend

from tests.helpers import NOW
from tests.test_kms_envelope import MemoryInstitutionProvider, institution_context


class EvidenceVaultLifecycleTests(unittest.TestCase):
    def _vault(
        self,
        path: Path,
        *,
        institution_id: str = "bank-a",
        provider: MemoryInstitutionProvider | None = None,
    ) -> tuple[EvidenceVault, SQLiteEvidenceVaultBackend, MemoryInstitutionProvider]:
        provider = provider or MemoryInstitutionProvider()
        backend = SQLiteEvidenceVaultBackend(path, institution_id=institution_id)
        vault = EvidenceVault(
            institution_context=institution_context(institution_id),
            provider=provider,
            backend=backend,
        )
        return vault, backend, provider

    def _ingest(self, vault: EvidenceVault, *, retention_days: int = 30) -> bytes:
        raw = b"vault-evidence: account=synthetic-001; result=controlled"
        vault.ingest(
            raw,
            engagement_id="ENG-VAULT-001",
            evidence_id="EV-VAULT-001",
            title="Synthetic controlled test evidence",
            classification=DataClassification.RESTRICTED,
            media_type="text/plain",
            source_system="payments-lab",
            collected_by="operator-001",
            collected_at=NOW,
            retention_until=(NOW + timedelta(days=retention_days)).date(),
            actor_id="operator-001",
            now=NOW + timedelta(minutes=1),
        )
        return raw

    def test_encrypted_at_rest_and_access_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.sqlite"
            vault, backend, _ = self._vault(path)
            raw = self._ingest(vault)
            stored_bytes = path.read_bytes()
            self.assertNotIn(raw, stored_bytes)
            record = backend.load_record("EV-VAULT-001")
            self.assertEqual(record.envelope.object_type, "evidence_vault")
            self.assertEqual(record.envelope.institution_id, "bank-a")
            self.assertEqual(
                vault.access(
                    "EV-VAULT-001",
                    actor_id="auditor-001",
                    purpose="Verify evidence integrity.",
                    now=NOW + timedelta(minutes=2),
                ),
                raw,
            )
            self.assertEqual(vault.verify("EV-VAULT-001").custody_event_count, 2)
            backend.close()

    def test_same_evidence_id_is_isolated_between_institutions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.sqlite"
            provider = MemoryInstitutionProvider()
            bank_a, backend_a, _ = self._vault(path, institution_id="bank-a", provider=provider)
            raw = self._ingest(bank_a)
            backend_a.close()
            bank_b, backend_b, _ = self._vault(path, institution_id="bank-b", provider=provider)
            with self.assertRaises(EvidenceVaultError):
                bank_b.verify("EV-VAULT-001")
            bank_b.ingest(
                b"bank-b independent evidence",
                engagement_id="ENG-VAULT-001",
                evidence_id="EV-VAULT-001",
                title="Bank B synthetic evidence",
                classification=DataClassification.CONFIDENTIAL,
                media_type="text/plain",
                source_system="identity-lab",
                collected_by="operator-b",
                collected_at=NOW,
                retention_until=(NOW + timedelta(days=30)).date(),
                actor_id="operator-b",
                now=NOW + timedelta(minutes=1),
            )
            self.assertNotEqual(
                bank_b.access(
                    "EV-VAULT-001",
                    actor_id="auditor-b",
                    purpose="Read bank B evidence.",
                    now=NOW + timedelta(minutes=2),
                ),
                raw,
            )
            backend_b.close()

    def test_legal_hold_blocks_deletion_after_retention_until_released(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, backend, _ = self._vault(Path(directory) / "vault.sqlite")
            self._ingest(vault, retention_days=1)
            vault.apply_legal_hold(
                "EV-VAULT-001",
                hold_id="CASE-2026-001",
                reason="Regulatory investigation hold.",
                actor_id="legal-001",
                now=NOW + timedelta(hours=1),
            )
            after_retention = NOW + timedelta(days=2)
            blocked = vault.deletion_eligibility("EV-VAULT-001", now=after_retention)
            self.assertFalse(blocked.eligible)
            self.assertEqual(blocked.reasons, ("legal_hold_active",))
            vault.release_legal_hold(
                "EV-VAULT-001",
                hold_id="CASE-2026-001",
                reason="Investigation closed.",
                actor_id="legal-002",
                now=after_retention + timedelta(minutes=1),
            )
            eligible = vault.deletion_eligibility(
                "EV-VAULT-001", now=after_retention + timedelta(minutes=2)
            )
            self.assertTrue(eligible.eligible)
            self.assertEqual(eligible.reasons, ())
            backend.close()

    def test_retention_can_only_move_forward_and_hold_id_cannot_be_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, backend, _ = self._vault(Path(directory) / "vault.sqlite")
            self._ingest(vault, retention_days=10)
            extended = vault.extend_retention(
                "EV-VAULT-001",
                retention_until=(NOW + timedelta(days=20)).date(),
                actor_id="records-001",
                reason="Extend regulated retention.",
                now=NOW + timedelta(hours=1),
            )
            self.assertEqual(extended.retention_until, (NOW + timedelta(days=20)).date())
            with self.assertRaises(EvidenceVaultError):
                vault.extend_retention(
                    "EV-VAULT-001",
                    retention_until=(NOW + timedelta(days=15)).date(),
                    actor_id="records-001",
                    reason="Attempt to shorten retention.",
                    now=NOW + timedelta(hours=2),
                )
            vault.apply_legal_hold(
                "EV-VAULT-001",
                hold_id="CASE-1",
                reason="Case open.",
                actor_id="legal-001",
                now=NOW + timedelta(hours=3),
            )
            vault.release_legal_hold(
                "EV-VAULT-001",
                hold_id="CASE-1",
                reason="Case closed.",
                actor_id="legal-002",
                now=NOW + timedelta(hours=4),
            )
            with self.assertRaises(EvidenceVaultError):
                vault.apply_legal_hold(
                    "EV-VAULT-001",
                    hold_id="CASE-1",
                    reason="Identifier reuse attempt.",
                    actor_id="legal-003",
                    now=NOW + timedelta(hours=5),
                )
            backend.close()

    def test_deletion_approval_does_not_destroy_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault, backend, _ = self._vault(Path(directory) / "vault.sqlite")
            raw = self._ingest(vault, retention_days=1)
            approval_time = NOW + timedelta(days=2)
            eligibility = vault.approve_deletion(
                "EV-VAULT-001",
                actor_id="records-governor",
                rationale="Retention expired and no legal hold remains.",
                now=approval_time,
            )
            self.assertTrue(eligibility.eligible)
            self.assertFalse(backend.metadata()["destructive_delete_supported"])
            events = backend.load_events("EV-VAULT-001")
            self.assertFalse(events[-1].details["destructive_delete_executed"])
            self.assertEqual(
                vault.access(
                    "EV-VAULT-001",
                    actor_id="auditor-001",
                    purpose="Confirm approval did not destroy evidence.",
                    now=approval_time + timedelta(minutes=1),
                ),
                raw,
            )
            backend.close()

    def test_recovery_preserves_encryption_and_custody_and_rejects_cross_tenant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            provider = MemoryInstitutionProvider()
            source, source_backend, _ = self._vault(
                Path(directory) / "source.sqlite", provider=provider
            )
            raw = self._ingest(source)
            bundle = source.export_recovery_bundle(
                "EV-VAULT-001",
                actor_id="custodian-001",
                recipient="secondary-vault",
                purpose="Controlled disaster-recovery export.",
                now=NOW + timedelta(hours=1),
            )
            target, target_backend, _ = self._vault(
                Path(directory) / "target.sqlite", provider=provider
            )
            restored = target.restore_recovery_bundle(
                bundle,
                actor_id="custodian-002",
                purpose="Controlled disaster-recovery restore.",
                now=NOW + timedelta(hours=2),
            )
            self.assertEqual(restored.custody_event_count, 3)
            self.assertEqual(
                target.access(
                    "EV-VAULT-001",
                    actor_id="auditor-001",
                    purpose="Verify recovered evidence.",
                    now=NOW + timedelta(hours=3),
                ),
                raw,
            )
            wrong, wrong_backend, _ = self._vault(
                Path(directory) / "wrong.sqlite",
                institution_id="bank-b",
                provider=provider,
            )
            with self.assertRaises(EvidenceVaultError):
                wrong.restore_recovery_bundle(
                    bundle,
                    actor_id="custodian-b",
                    purpose="Cross-tenant restore must fail.",
                    now=NOW + timedelta(hours=2),
                )
            source_backend.close()
            target_backend.close()
            wrong_backend.close()


if __name__ == "__main__":
    unittest.main()
