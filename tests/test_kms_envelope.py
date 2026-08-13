from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finredops.audit import AuditChain
from finredops.aws_kms import AwsKmsProvider
from finredops.crypto_provider import (
    CryptoProviderError,
    ProviderSignature,
    WrappedDataKey,
)
from finredops.demo import build_demo_service
from finredops.envelope import (
    EnvelopeEncryptedArtifact,
    EnvelopeError,
    decrypt_bytes,
    encrypt_bytes,
    envelope_from_document,
)
from finredops.institution import InstitutionKeyReference, InstitutionSecurityContext
from finredops.models import ExecutionReceipt, ExecutionStatus, sha256_digest
from finredops.signed_evidence import (
    sign_audit_chain,
    sign_execution_receipt,
    verify_audit_chain_signature,
    verify_execution_receipt_signature,
)
from finredops.store import SQLiteGovernanceStore

from tests.helpers import NOW


class MemoryInstitutionProvider:
    provider_name = "other"

    def __init__(self) -> None:
        self._wrap_keys = {
            "kms://data-v1": AESGCM.generate_key(bit_length=256),
            "kms://data-v2": AESGCM.generate_key(bit_length=256),
        }
        self._signing_keys = {
            "hsm://audit-v1": Ed25519PrivateKey.generate(),
        }

    @staticmethod
    def _aad(context: Mapping[str, str]) -> bytes:
        return json.dumps(dict(sorted(context.items())), separators=(",", ":")).encode()

    def wrap_data_key(
        self,
        key_ref: str,
        plaintext_key: bytes,
        *,
        context: Mapping[str, str],
    ) -> WrappedDataKey:
        key = self._wrap_keys[key_ref]
        nonce = b"N" * 12
        return WrappedDataKey(
            nonce + AESGCM(key).encrypt(nonce, plaintext_key, self._aad(context)),
            "TEST-AES-GCM-WRAP",
        )

    def unwrap_data_key(
        self,
        key_ref: str,
        wrapped_key: WrappedDataKey,
        *,
        context: Mapping[str, str],
    ) -> bytes:
        if wrapped_key.algorithm != "TEST-AES-GCM-WRAP":
            raise CryptoProviderError("wrong wrapping algorithm")
        key = self._wrap_keys[key_ref]
        nonce, ciphertext = wrapped_key.ciphertext[:12], wrapped_key.ciphertext[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, self._aad(context))

    def sign_digest(self, key_ref: str, digest: bytes) -> ProviderSignature:
        return ProviderSignature(self._signing_keys[key_ref].sign(digest), "ED25519")

    def verify_digest(
        self,
        key_ref: str,
        digest: bytes,
        signature: ProviderSignature,
    ) -> bool:
        if signature.algorithm != "ED25519":
            return False
        try:
            self._signing_keys[key_ref].public_key().verify(signature.signature, digest)
        except InvalidSignature:
            return False
        return True


def institution_context(
    institution_id: str = "bank-a",
    *,
    data_key_id: str = "data-v1",
    data_key_ref: str = "kms://data-v1",
    old_data_key: bool = False,
) -> InstitutionSecurityContext:
    refs = []
    if old_data_key:
        refs.append(
            InstitutionKeyReference(
                key_id="data-v1",
                purpose="data_encryption",
                provider="other",
                key_ref="kms://data-v1",
                status="retiring",
            )
        )
    refs.extend(
        [
            InstitutionKeyReference(
                key_id=data_key_id,
                purpose="data_encryption",
                provider="other",
                key_ref=data_key_ref,
            ),
            InstitutionKeyReference(
                key_id="audit-v1",
                purpose="audit_signing",
                provider="other",
                key_ref="hsm://audit-v1",
            ),
        ]
    )
    return InstitutionSecurityContext(
        institution_id=institution_id,
        institution_name="Example Institution",
        key_references=tuple(refs),
    )


class EnvelopeEncryptionTests(unittest.TestCase):
    def test_envelope_round_trip_uses_fresh_dek_and_authenticated_context(self) -> None:
        provider = MemoryInstitutionProvider()
        context = institution_context()
        first = encrypt_bytes(
            b"regulated evidence",
            institution_context=context,
            provider=provider,
            object_type="evidence",
            object_id="EV-001",
            created_at=NOW,
        )
        second = encrypt_bytes(
            b"regulated evidence",
            institution_context=context,
            provider=provider,
            object_type="evidence",
            object_id="EV-001",
            created_at=NOW,
        )
        self.assertEqual(
            decrypt_bytes(first, institution_context=context, provider=provider),
            b"regulated evidence",
        )
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertNotEqual(first.wrapped_dek, second.wrapped_dek)
        self.assertEqual(first.content_algorithm, "AES-256-GCM")

    def test_cross_institution_and_object_replay_fail_closed(self) -> None:
        provider = MemoryInstitutionProvider()
        context = institution_context()
        artifact = encrypt_bytes(
            b"secret",
            institution_context=context,
            provider=provider,
            object_type="snapshot",
            object_id="ENG-1:1",
            created_at=NOW,
        )
        with self.assertRaises(EnvelopeError):
            decrypt_bytes(
                artifact,
                institution_context=institution_context("bank-b"),
                provider=provider,
            )
        altered = EnvelopeEncryptedArtifact(
            **{**artifact.core(), "object_id": "ENG-2:1"}
        )
        altered = EnvelopeEncryptedArtifact(
            **altered.core(), envelope_digest=altered.digest()
        )
        with self.assertRaises(EnvelopeError):
            decrypt_bytes(altered, institution_context=context, provider=provider)

    def test_envelope_document_digest_tampering_is_rejected(self) -> None:
        provider = MemoryInstitutionProvider()
        artifact = encrypt_bytes(
            b"secret",
            institution_context=institution_context(),
            provider=provider,
            object_type="evidence",
            object_id="EV-002",
            created_at=NOW,
        ).as_dict()
        artifact["plaintext_digest"] = "f" * 64
        with self.assertRaises(EnvelopeError):
            envelope_from_document(artifact)

    def test_old_retiring_data_key_can_decrypt_after_rotation(self) -> None:
        provider = MemoryInstitutionProvider()
        old_context = institution_context()
        artifact = encrypt_bytes(
            b"old record",
            institution_context=old_context,
            provider=provider,
            object_type="snapshot",
            object_id="ENG-1:1",
            created_at=NOW,
        )
        rotated = institution_context(
            data_key_id="data-v2",
            data_key_ref="kms://data-v2",
            old_data_key=True,
        )
        self.assertEqual(
            decrypt_bytes(artifact, institution_context=rotated, provider=provider),
            b"old record",
        )


class EncryptedStoreTests(unittest.TestCase):
    def test_new_snapshot_and_audit_payloads_are_envelope_encrypted_at_rest(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        provider = MemoryInstitutionProvider()
        context = institution_context()
        with SQLiteGovernanceStore(
            ":memory:",
            institution_id="bank-a",
            security_context=context,
            crypto_provider=provider,
        ) as store:
            store.save_snapshot(snapshot, now=NOW)
            store.persist_audit_chain(engagement_id, service.audit)
            row = store._connection.execute(
                "SELECT snapshot_json, protection_mode FROM engagement_snapshots"
            ).fetchone()
            self.assertEqual(row["protection_mode"], "envelope_v1")
            self.assertNotIn(snapshot["engagement"]["name"], row["snapshot_json"])
            audit_row = store._connection.execute(
                "SELECT event_json, protection_mode FROM audit_events ORDER BY sequence LIMIT 1"
            ).fetchone()
            self.assertEqual(audit_row["protection_mode"], "envelope_v1")
            self.assertNotIn("engagement.registered", audit_row["event_json"])
            self.assertEqual(store.load_latest(engagement_id), snapshot)
            self.assertEqual(store.verify_persisted_audit(engagement_id), (True, ()))
            metadata = store.metadata()
            self.assertTrue(metadata["encryption_at_rest_verified"])
            self.assertEqual(metadata["plaintext_legacy_record_count"], 0)

    def test_plaintext_legacy_rows_can_be_rewritten_under_institution_kek(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        snapshot = service.snapshot(engagement_id)
        provider = MemoryInstitutionProvider()
        context = institution_context()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "finredops.db"
            with SQLiteGovernanceStore(database, institution_id="bank-a") as legacy:
                legacy.save_snapshot(snapshot, now=NOW)
                legacy.persist_audit_chain(engagement_id, service.audit)
                self.assertFalse(legacy.metadata()["encryption_at_rest_verified"])
            with SQLiteGovernanceStore(
                database,
                institution_id="bank-a",
                security_context=context,
                crypto_provider=provider,
            ) as protected:
                result = protected.encrypt_existing_records(now=NOW + timedelta(minutes=1))
                self.assertEqual(result["snapshots_encrypted"], 1)
                self.assertEqual(result["audit_events_encrypted"], len(service.audit.events))
                self.assertEqual(protected.load_latest(engagement_id), snapshot)
                self.assertEqual(protected.verify_persisted_audit(engagement_id), (True, ()))
                self.assertTrue(protected.metadata()["encryption_at_rest_verified"])


class KeyBackedEvidenceSignatureTests(unittest.TestCase):
    def test_audit_chain_signature_is_bound_to_chain_and_institution(self) -> None:
        service, engagement_id = build_demo_service(now=NOW)
        provider = MemoryInstitutionProvider()
        context = institution_context()
        artifact = sign_audit_chain(
            engagement_id,
            service.audit,
            institution_context=context,
            provider=provider,
            signed_at=NOW,
        )
        self.assertTrue(
            verify_audit_chain_signature(
                engagement_id,
                service.audit,
                artifact,
                institution_context=context,
                provider=provider,
            )
        )
        tampered = AuditChain(service.audit.events)
        tampered.append(
            timestamp=NOW + timedelta(minutes=1),
            actor_id="auditor",
            event_type="test.additional",
            engagement_id=engagement_id,
            payload={"extra": True},
        )
        self.assertFalse(
            verify_audit_chain_signature(
                engagement_id,
                tampered,
                artifact,
                institution_context=context,
                provider=provider,
            )
        )
        self.assertFalse(
            verify_audit_chain_signature(
                engagement_id,
                service.audit,
                artifact,
                institution_context=institution_context("bank-b"),
                provider=provider,
            )
        )

    def test_execution_receipt_signature_detects_receipt_change(self) -> None:
        provider = MemoryInstitutionProvider()
        context = institution_context()
        evidence = {"safe": True}
        receipt = ExecutionReceipt(
            execution_id="EXEC-0001",
            proposal_id="PROP-0001",
            proposal_digest="a" * 64,
            status=ExecutionStatus.SIMULATED,
            runner="synthetic",
            started_at=NOW,
            finished_at=NOW,
            evidence=evidence,
            evidence_digest=sha256_digest(evidence),
        )
        artifact = sign_execution_receipt(
            receipt,
            institution_context=context,
            provider=provider,
            signed_at=NOW,
        )
        self.assertTrue(
            verify_execution_receipt_signature(
                receipt,
                artifact,
                institution_context=context,
                provider=provider,
            )
        )
        changed_evidence = {"safe": False}
        changed = replace(
            receipt,
            evidence=changed_evidence,
            evidence_digest=sha256_digest(changed_evidence),
        )
        self.assertFalse(
            verify_execution_receipt_signature(
                changed,
                artifact,
                institution_context=context,
                provider=provider,
            )
        )


class FakeAwsKmsClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def encrypt(self, **kwargs):
        self.calls.append(("encrypt", kwargs))
        return {"CiphertextBlob": b"wrapped"}

    def decrypt(self, **kwargs):
        self.calls.append(("decrypt", kwargs))
        return {"Plaintext": b"D" * 32}

    def sign(self, **kwargs):
        self.calls.append(("sign", kwargs))
        return {"Signature": b"signature", "SigningAlgorithm": kwargs["SigningAlgorithm"]}

    def verify(self, **kwargs):
        self.calls.append(("verify", kwargs))
        return {"SignatureValid": True}


class AwsKmsProviderContractTests(unittest.TestCase):
    def test_adapter_uses_encryption_context_and_digest_signing(self) -> None:
        client = FakeAwsKmsClient()
        provider = AwsKmsProvider(
            client,
            signing_algorithms={"arn:sign": "ECDSA_SHA_256"},
        )
        context = {"institution-id": "bank-a", "object-binding": "x"}
        wrapped = provider.wrap_data_key("arn:data", b"D" * 32, context=context)
        self.assertEqual(wrapped.algorithm, "AWS_KMS_ENCRYPT")
        self.assertEqual(
            provider.unwrap_data_key("arn:data", wrapped, context=context), b"D" * 32
        )
        signature = provider.sign_digest("arn:sign", b"H" * 32)
        self.assertTrue(provider.verify_digest("arn:sign", b"H" * 32, signature))
        encrypt_call = client.calls[0][1]
        self.assertEqual(encrypt_call["EncryptionContext"], context)
        sign_call = next(kwargs for name, kwargs in client.calls if name == "sign")
        self.assertEqual(sign_call["MessageType"], "DIGEST")
        self.assertEqual(sign_call["SigningAlgorithm"], "ECDSA_SHA_256")

    def test_adapter_rejects_non_sha256_signing_algorithm(self) -> None:
        with self.assertRaises(CryptoProviderError):
            AwsKmsProvider(
                FakeAwsKmsClient(),
                signing_algorithms={"arn:sign": "ECDSA_SHA_384"},
            )


if __name__ == "__main__":
    unittest.main()
