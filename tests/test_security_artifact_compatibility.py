from __future__ import annotations

import unittest

from finredops.envelope import EnvelopeError, encrypt_bytes, envelope_from_document
from finredops.workload_identity import WorkloadIdentityError, workload_identity_from_document

from tests.helpers import NOW
from tests.test_kms_envelope import MemoryInstitutionProvider, institution_context
from tests.test_workload_execution import objects


class SecurityArtifactCompatibilityTests(unittest.TestCase):
    def test_future_workload_identity_schema_is_not_reinterpreted(self) -> None:
        _institution, _provider, _engagement, _proposal, _policy, _egress, identity, *_ = objects()
        document = identity.as_dict()
        document["schema_version"] = "finredops.workload-identity-attestation.v2"
        with self.assertRaises(WorkloadIdentityError):
            workload_identity_from_document(document)

    def test_future_envelope_schema_is_not_reinterpreted(self) -> None:
        provider = MemoryInstitutionProvider()
        context = institution_context()
        artifact = encrypt_bytes(
            b"compatibility-test",
            institution_context=context,
            provider=provider,
            object_type="evidence",
            object_id="EV-RC-COMPAT-001",
            created_at=NOW,
        )
        document = artifact.as_dict()
        document["schema_version"] = "finredops.envelope-encrypted-artifact.v2"
        with self.assertRaises(EnvelopeError):
            envelope_from_document(document)


if __name__ == "__main__":
    unittest.main()
