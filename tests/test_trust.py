from __future__ import annotations

import base64
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finredops.entrypoint import entrypoint
from finredops.intake import EvidenceIntakeBatch, import_sarif_file
from finredops.regulations import AssessmentType
from finredops.review import review_from_draft, review_template_document
from finredops.trust import (
    ReviewTrustError,
    identity_assertion_from_document,
    identity_assertion_signing_document,
    lifecycle_event_from_draft,
    resolve_trusted_reviews,
    trust_bundle_from_document,
)

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"
ASSESSMENT = AssessmentType.VENDOR_SOURCE_CODE_REVIEW
ENGAGEMENT_ID = "FRX-DEMO-2026-001"
ISSUER = "idp.example.test"
KEY_ID = "reviewer-key-2026"
AS_OF = datetime(2026, 8, 13, 11, 0, tzinfo=timezone.utc)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _canonical(document: object) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _review_draft(
    batch: EvidenceIntakeBatch,
    index: int,
    *,
    disposition: str,
    reviewed_at: str,
    reviewer_id: str = "tester:bilge-kayali",
) -> dict[str, object]:
    finding = batch.findings[index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT)
    document.update(
        {
            "disposition": disposition,
            "reviewer_id": reviewer_id,
            "qualification_evidence_ref": "qualification-evidence://person/tester/current",
            "reviewed_at": reviewed_at,
            "rationale": (
                "The qualified tester reviewed the retained synthetic evidence and "
                "recorded a complete human disposition for this controlled test case."
            ),
            "validation_evidence_refs": [f"evidence://review/{finding.fingerprint}"],
        }
    )
    if disposition == "confirmed":
        document.update(
            {
                "final_severity": finding.machine_severity.value,
                "business_impact": (
                    "The synthetic condition could weaken a financial security boundary "
                    "if the same defect were present in an authorized production design."
                ),
                "recommendation": (
                    "Apply the defensive control, retain remediation evidence, and perform "
                    "an independent retest before closure."
                ),
                "control_refs": ["TR-BDDK-BSEBY-22-4-5"],
            }
        )
    return document


class TrustFixture:
    def __init__(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.bundle_document = {
            "schema_version": "finredops.reviewer-trust-bundle.v1",
            "bundle_id": "synthetic-trust-2026",
            "keys": [
                {
                    "issuer": ISSUER,
                    "key_id": KEY_ID,
                    "algorithm": "Ed25519",
                    "public_key": _b64url(public),
                    "roles": ["qualified_tester", "review_governor"],
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                }
            ],
        }
        self.bundle = trust_bundle_from_document(self.bundle_document)

    def assertion(self, *, batch: EvidenceIntakeBatch, item: object, lifecycle: bool = False):
        if lifecycle:
            subject = item.actor_id  # type: ignore[attr-defined]
            purpose = "review_lifecycle"
            role = "review_governor"
            object_id = item.event_id  # type: ignore[attr-defined]
            object_digest = item.digest()  # type: ignore[attr-defined]
            finding_id = item.finding_id  # type: ignore[attr-defined]
        else:
            subject = item.reviewer_id  # type: ignore[attr-defined]
            purpose = "finding_review"
            role = "qualified_tester"
            object_id = item.review_id  # type: ignore[attr-defined]
            object_digest = item.digest()  # type: ignore[attr-defined]
            finding_id = item.finding_id  # type: ignore[attr-defined]
        request = identity_assertion_signing_document(
            {
                "issuer": ISSUER,
                "subject": subject,
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "purpose": purpose,
                "role": role,
                "engagement_id": ENGAGEMENT_ID,
                "batch_id": batch.batch_id,
                "batch_digest": batch.digest(),
                "finding_id": finding_id,
                "object_id": object_id,
                "object_digest": object_digest,
                "issued_at": "2026-08-13T10:00:00Z",
                "expires_at": "2026-08-13T12:00:00Z",
            }
        )
        signature = self.private_key.sign(_canonical(request))
        return identity_assertion_from_document({**request, "signature": _b64url(signature)})


class ReviewTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.batch = import_sarif_file(SYNTHETIC_SARIF)
        self.fixture = TrustFixture()

    def test_signed_review_is_bound_to_engagement_intake_and_subject(self) -> None:
        review = review_from_draft(
            _review_draft(
                self.batch, 0, disposition="confirmed", reviewed_at="2026-08-12T09:00:00Z"
            ),
            self.batch,
        )
        assertion = self.fixture.assertion(batch=self.batch, item=review)
        resolution = resolve_trusted_reviews(
            self.batch,
            (review,),
            (),
            (assertion,),
            self.fixture.bundle,
            engagement_id=ENGAGEMENT_ID,
            as_of=AS_OF,
        )
        self.assertEqual(resolution.authoritative_reviews, (review,))
        self.assertTrue(resolution.as_dict()["cryptographic_signatures_verified"])
        self.assertFalse(resolution.as_dict()["external_idp_protocol_verified"])

        with self.assertRaises(ReviewTrustError):
            resolve_trusted_reviews(
                self.batch,
                (review,),
                (),
                (assertion,),
                self.fixture.bundle,
                engagement_id="FRX-OTHER-ENGAGEMENT",
                as_of=AS_OF,
            )

    def test_signature_tamper_fails_closed(self) -> None:
        review = review_from_draft(
            _review_draft(
                self.batch, 0, disposition="confirmed", reviewed_at="2026-08-12T09:00:00Z"
            ),
            self.batch,
        )
        assertion = self.fixture.assertion(batch=self.batch, item=review)
        changed = assertion.as_dict()
        changed["signature"] = _b64url(b"\x00" * 64)
        tampered = identity_assertion_from_document(changed)
        with self.assertRaises(ReviewTrustError):
            resolve_trusted_reviews(
                self.batch,
                (review,),
                (),
                (tampered,),
                self.fixture.bundle,
                engagement_id=ENGAGEMENT_ID,
                as_of=AS_OF,
            )

    def test_supersession_and_revocation_preserve_history(self) -> None:
        first = review_from_draft(
            _review_draft(
                self.batch, 0, disposition="confirmed", reviewed_at="2026-08-12T09:00:00Z"
            ),
            self.batch,
        )
        replacement = review_from_draft(
            _review_draft(
                self.batch, 0, disposition="false_positive", reviewed_at="2026-08-12T10:00:00Z"
            ),
            self.batch,
        )
        event = lifecycle_event_from_draft(
            {
                "batch_id": self.batch.batch_id,
                "batch_digest": self.batch.digest(),
                "finding_id": first.finding_id,
                "action": "supersede",
                "prior_review_id": first.review_id,
                "prior_review_digest": first.digest(),
                "replacement_review_id": replacement.review_id,
                "replacement_review_digest": replacement.digest(),
                "actor_id": "review-governor:security",
                "event_at": "2026-08-12T10:30:00Z",
                "reason": "New retained evidence demonstrates that the original disposition must be replaced.",
            }
        )
        assertions = (
            self.fixture.assertion(batch=self.batch, item=first),
            self.fixture.assertion(batch=self.batch, item=replacement),
            self.fixture.assertion(batch=self.batch, item=event, lifecycle=True),
        )
        resolution = resolve_trusted_reviews(
            self.batch,
            (first, replacement),
            (event,),
            assertions,
            self.fixture.bundle,
            engagement_id=ENGAGEMENT_ID,
            as_of=AS_OF,
        )
        self.assertEqual(resolution.authoritative_reviews, (replacement,))
        self.assertEqual(len(resolution.lifecycle_event_ids), 1)

        revoke = lifecycle_event_from_draft(
            {
                "batch_id": self.batch.batch_id,
                "batch_digest": self.batch.digest(),
                "finding_id": replacement.finding_id,
                "action": "revoke",
                "prior_review_id": replacement.review_id,
                "prior_review_digest": replacement.digest(),
                "replacement_review_id": "",
                "replacement_review_digest": "",
                "actor_id": "review-governor:security",
                "event_at": "2026-08-12T11:00:00Z",
                "reason": "The replacement review is revoked pending a new independent qualified assessment.",
            }
        )
        resolution = resolve_trusted_reviews(
            self.batch,
            (first, replacement),
            (event, revoke),
            (*assertions, self.fixture.assertion(batch=self.batch, item=revoke, lifecycle=True)),
            self.fixture.bundle,
            engagement_id=ENGAGEMENT_ID,
            as_of=AS_OF,
        )
        self.assertEqual(resolution.authoritative_reviews, ())
        self.assertEqual(resolution.revoked_finding_ids, (replacement.finding_id,))

    def test_trusted_promotion_uses_only_signed_authoritative_reviews(self) -> None:
        first = review_from_draft(
            _review_draft(
                self.batch, 0, disposition="confirmed", reviewed_at="2026-08-12T09:00:00Z"
            ),
            self.batch,
        )
        second = review_from_draft(
            _review_draft(
                self.batch, 1, disposition="false_positive", reviewed_at="2026-08-12T09:05:00Z"
            ),
            self.batch,
        )
        assertions = (
            self.fixture.assertion(batch=self.batch, item=first),
            self.fixture.assertion(batch=self.batch, item=second),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "intake.json"
            review1 = root / "review1.json"
            review2 = root / "review2.json"
            assertion1 = root / "assertion1.json"
            assertion2 = root / "assertion2.json"
            bundle = root / "trust-bundle.json"
            spec = root / "spec.json"
            output = root / "trusted"
            intake.write_text(json.dumps(self.batch.as_dict()), encoding="utf-8")
            review1.write_text(json.dumps(first.as_dict()), encoding="utf-8")
            review2.write_text(json.dumps(second.as_dict()), encoding="utf-8")
            assertion1.write_text(json.dumps(assertions[0].as_dict()), encoding="utf-8")
            assertion2.write_text(json.dumps(assertions[1].as_dict()), encoding="utf-8")
            bundle.write_text(json.dumps(self.fixture.bundle_document), encoding="utf-8")
            spec.write_text(
                json.dumps(
                    {
                        "schema_version": "finredops.reviewed-report-spec.v1",
                        "report_id": "FRX-RPT-TRUST-001",
                        "title": "Synthetic trusted-review security report",
                        "assessment_type": ASSESSMENT.value,
                        "organization": "Synthetic Financial Institution",
                        "period_start": "2026-08-12",
                        "period_end": "2026-08-13",
                        "issued_at": "2026-08-13T11:00:00Z",
                        "classification": "RESTRICTED — SYNTHETIC",
                        "rules_of_engagement_ref": "attachment://FRX-DEMO-2026-001/approved-roe",
                        "in_scope_assets": ["synthetic-source-repository"],
                        "excluded_assets": ["production-systems"],
                        "tester_organization": "Synthetic Independent Test Team",
                        "lead_tester": "Synthetic Qualified Tester",
                        "independence_declaration": "Synthetic reviewer is separate from development operations.",
                        "tester_qualifications": ["qualification-evidence://synthetic/tester"],
                        "methodology": [
                            "bounded SARIF 2.1.0 intake",
                            "externally signed qualified review",
                            "authoritative review lifecycle resolution",
                            "draft report promotion",
                        ],
                        "executive_summary": "Synthetic signed-review trust workflow validation.",
                        "limitations": ["Synthetic evidence only."],
                        "finding_metadata": {
                            first.finding_id: {
                                "affected_assets": [self.batch.findings[0].artifact_ref],
                                "owner": "Synthetic Engineering Owner",
                                "due_date": "2026-09-30",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = [
                "promote-trusted-reviewed-report",
                "--intake", str(intake),
                "--review", str(review1),
                "--review", str(review2),
                "--identity-assertion", str(assertion1),
                "--identity-assertion", str(assertion2),
                "--trust-bundle", str(bundle),
                "--engagement-id", ENGAGEMENT_ID,
                "--as-of", "2026-08-13T11:00:00Z",
                "--spec", str(spec),
                "--output-dir", str(output),
            ]
            captured = StringIO()
            with redirect_stdout(captured):
                result = entrypoint(args)
            self.assertEqual(result, 0, captured.getvalue())
            summary = json.loads(captured.getvalue())
            self.assertTrue(summary["valid"])
            self.assertFalse(summary["ready_for_issue"])
            self.assertEqual(summary["verified_assertion_count"], 2)
            trusted_manifest = json.loads(
                (output / "trusted-promotion-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(trusted_manifest["cryptographic_signatures_verified"])
            self.assertFalse(json.loads((output / "trust-resolution.json").read_text())["external_idp_protocol_verified"])


if __name__ == "__main__":
    unittest.main()
