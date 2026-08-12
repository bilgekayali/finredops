from __future__ import annotations

import unittest
from datetime import timedelta

from finredops.custody import (
    CustodyAction,
    EvidenceArtifact,
    EvidenceManifest,
    EvidenceRegistry,
    EvidenceType,
)
from finredops.models import DataClassification

from tests.helpers import NOW


def _artifact(*, locator: str = "evidence://ENG-1/result-1") -> EvidenceArtifact:
    return EvidenceArtifact(
        evidence_id="EVD-1",
        title="Synthetic result metadata",
        evidence_type=EvidenceType.TEST_RESULT,
        classification=DataClassification.RESTRICTED,
        content_sha256="a" * 64,
        size_bytes=128,
        media_type="application/json",
        source_system="synthetic fixture",
        collected_at=NOW - timedelta(minutes=2),
        collected_by="operator",
        locator=locator,
        description="No raw content is stored in the registry.",
        retention_until="2031-08-12",
        contains_personal_data=False,
        sanitized=True,
    )


class CustodyTests(unittest.TestCase):
    def test_registration_and_verification_form_valid_chain(self) -> None:
        registry = EvidenceRegistry("ENG-1")
        registry.register(_artifact(), actor_id="custodian", now=NOW)
        registry.record(
            "EVD-1",
            CustodyAction.VERIFIED,
            actor_id="reviewer",
            now=NOW + timedelta(seconds=1),
            purpose="Verify content digest.",
        )
        manifest = registry.manifest()
        self.assertEqual(manifest.verify(), (True, ()))
        self.assertFalse(manifest.as_dict()["raw_evidence_embedded"])
        self.assertEqual(
            EvidenceManifest.from_dict(manifest.as_dict()).digest(), manifest.digest()
        )

    def test_activity_after_disposal_is_rejected(self) -> None:
        registry = EvidenceRegistry("ENG-1")
        registry.register(_artifact(), actor_id="custodian", now=NOW)
        registry.record(
            "EVD-1",
            CustodyAction.DISPOSED,
            actor_id="custodian",
            now=NOW + timedelta(seconds=1),
            purpose="Retention period ended.",
        )
        with self.assertRaises(ValueError):
            registry.record(
                "EVD-1",
                CustodyAction.ACCESSED,
                actor_id="auditor",
                now=NOW + timedelta(seconds=2),
                purpose="Late access.",
            )

    def test_unapproved_locator_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _artifact(locator="https://raw-evidence.example.test/result")

    def test_manifest_tampering_is_rejected(self) -> None:
        registry = EvidenceRegistry("ENG-1")
        registry.register(_artifact(), actor_id="custodian", now=NOW)
        document = registry.manifest().as_dict()
        document["artifacts"][0]["description"] = "Changed"
        with self.assertRaises(ValueError):
            EvidenceManifest.from_dict(document)


if __name__ == "__main__":
    unittest.main()
