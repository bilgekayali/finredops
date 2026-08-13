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

from finredops.approval_keys import ApprovalKeyError, approval_trust_bundle_from_document
from finredops.entrypoint import entrypoint
from finredops.intake import EvidenceIntakeBatch, import_sarif_file
from finredops.models import sha256_digest
from finredops.regulations import AssessmentType
from finredops.reporting import ReportStatus, demo_regulatory_report, validate_report
from finredops.review import (
    review_from_draft,
    review_template_document,
    risk_acceptance_from_draft,
    risk_acceptance_template_document,
)
from finredops.signed_approvals import (
    SignedApprovalError,
    approval_signature_from_document,
    approval_signature_request,
    approve_report_with_signatures,
    verify_signed_risk_acceptances,
)
from finredops.trust import (
    identity_assertion_from_document,
    identity_assertion_signing_document,
    resolve_trusted_reviews,
    trust_bundle_from_document,
)

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"
ASSESSMENT = AssessmentType.VENDOR_SOURCE_CODE_REVIEW
ENGAGEMENT_ID = "FRX-DEMO-2026-001"
AS_OF = datetime(2026, 8, 13, 11, 0, tzinfo=timezone.utc)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _canonical(document: object) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _public(private_key: Ed25519PrivateKey) -> str:
    return _b64url(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _confirmed_draft(batch: EvidenceIntakeBatch, index: int, reviewed_at: str) -> dict[str, object]:
    finding = batch.findings[index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT)
    document.update(
        {
            "disposition": "confirmed",
            "reviewer_id": "tester:synthetic-qualified",
            "qualification_evidence_ref": "qualification-evidence://synthetic/tester/current",
            "reviewed_at": reviewed_at,
            "rationale": "The qualified tester reviewed retained synthetic evidence and confirmed the controlled finding.",
            "validation_evidence_refs": [f"evidence://review/{finding.fingerprint}"],
            "final_severity": finding.machine_severity.value,
            "business_impact": "The synthetic condition could weaken a regulated financial security boundary if present in an authorized environment.",
            "recommendation": "Apply the documented defensive control and retain independent retest evidence before closure.",
            "control_refs": ["TR-BDDK-BSEBY-22-4-5"],
        }
    )
    return document


def _false_positive_draft(batch: EvidenceIntakeBatch, index: int, reviewed_at: str) -> dict[str, object]:
    finding = batch.findings[index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT)
    document.update(
        {
            "disposition": "false_positive",
            "reviewer_id": "tester:synthetic-qualified",
            "qualification_evidence_ref": "qualification-evidence://synthetic/tester/current",
            "reviewed_at": reviewed_at,
            "rationale": "The qualified tester reviewed retained synthetic evidence and determined that the candidate is a false positive.",
            "validation_evidence_refs": [f"evidence://review/{finding.fingerprint}"],
        }
    )
    return document


class ApprovalFixture:
    def __init__(self) -> None:
        self.risk_key = Ed25519PrivateKey.generate()
        self.approver1_key = Ed25519PrivateKey.generate()
        self.approver2_key = Ed25519PrivateKey.generate()
        self.bundle_document = {
            "schema_version": "finredops.approval-trust-bundle.v1",
            "bundle_id": "synthetic-approval-trust-2026",
            "keys": [
                {
                    "issuer": "approval-idp.example.test",
                    "key_id": "risk-owner-key",
                    "algorithm": "Ed25519",
                    "public_key": _public(self.risk_key),
                    "roles": ["business_risk_owner"],
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                },
                {
                    "issuer": "approval-idp.example.test",
                    "key_id": "report-key-1",
                    "algorithm": "Ed25519",
                    "public_key": _public(self.approver1_key),
                    "roles": ["report_approver"],
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                },
                {
                    "issuer": "approval-idp.example.test",
                    "key_id": "report-key-2",
                    "algorithm": "Ed25519",
                    "public_key": _public(self.approver2_key),
                    "roles": ["report_approver"],
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                },
            ],
        }
        self.bundle = approval_trust_bundle_from_document(self.bundle_document)

    def signature(self, request: dict[str, object], key: Ed25519PrivateKey):
        return approval_signature_from_document(
            {**request, "signature": _b64url(key.sign(_canonical(request)))}
        )


class SignedApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.batch = import_sarif_file(SYNTHETIC_SARIF)
        self.fixture = ApprovalFixture()
        self.review = review_from_draft(
            _confirmed_draft(self.batch, 0, "2026-08-12T09:00:00Z"), self.batch
        )
        acceptance_draft = risk_acceptance_template_document(self.review)
        acceptance_draft.update(
            {
                "accepted_by": "risk-owner:payments",
                "approved_at": "2026-08-13T10:00:00Z",
                "expires_on": "2027-02-13",
                "approval_evidence_ref": "attachment://approvals/RISK-SYN-001",
                "rationale": "The accountable business owner accepts the documented residual synthetic risk until the approved remediation date.",
                "compensating_controls": ["Restricted access and daily monitoring remain active until remediation and retest."],
            }
        )
        self.acceptance = risk_acceptance_from_draft(acceptance_draft, self.batch, self.review)

    def _risk_signature(self, context_digest: str):
        request = approval_signature_request(
            {
                "issuer": "approval-idp.example.test",
                "subject": self.acceptance.accepted_by,
                "key_id": "risk-owner-key",
                "algorithm": "Ed25519",
                "purpose": "risk_acceptance",
                "role": "business_risk_owner",
                "engagement_id": ENGAGEMENT_ID,
                "object_type": "risk_acceptance",
                "object_id": self.acceptance.acceptance_id,
                "object_digest": self.acceptance.digest(),
                "context_digest": context_digest,
                "issued_at": "2026-08-13T10:30:00Z",
                "expires_at": "2026-08-13T12:00:00Z",
            }
        )
        return self.fixture.signature(request, self.fixture.risk_key)

    def _report_signature(self, report: object, manifest: dict[str, object], subject: str, key_id: str, key: Ed25519PrivateKey):
        request = approval_signature_request(
            {
                "issuer": "approval-idp.example.test",
                "subject": subject,
                "key_id": key_id,
                "algorithm": "Ed25519",
                "purpose": "report_approval",
                "role": "report_approver",
                "engagement_id": ENGAGEMENT_ID,
                "object_type": "regulatory_report",
                "object_id": report.report_id,
                "object_digest": report.digest(),
                "context_digest": manifest["trusted_promotion_digest"],
                "issued_at": "2026-08-13T10:30:00Z",
                "expires_at": "2026-08-13T12:00:00Z",
            }
        )
        return self.fixture.signature(request, key)

    def test_approval_keys_are_role_separated_from_reviewer_keys(self) -> None:
        invalid = json.loads(json.dumps(self.fixture.bundle_document))
        invalid["keys"][0]["roles"] = ["qualified_tester"]
        with self.assertRaises(ApprovalKeyError):
            approval_trust_bundle_from_document(invalid)

    def test_signed_risk_acceptance_is_context_bound_and_tamper_evident(self) -> None:
        context = "a" * 64
        signature = self._risk_signature(context)
        resolution = verify_signed_risk_acceptances(
            self.batch,
            (self.review,),
            (self.acceptance,),
            (signature,),
            self.fixture.bundle,
            engagement_id=ENGAGEMENT_ID,
            review_trust_resolution_digest=context,
            as_of=AS_OF,
        )
        self.assertEqual(resolution.acceptance_ids, (self.acceptance.acceptance_id,))
        self.assertTrue(resolution.as_dict()["cryptographic_signatures_verified"])

        with self.assertRaises(SignedApprovalError):
            verify_signed_risk_acceptances(
                self.batch,
                (self.review,),
                (self.acceptance,),
                (signature,),
                self.fixture.bundle,
                engagement_id=ENGAGEMENT_ID,
                review_trust_resolution_digest="b" * 64,
                as_of=AS_OF,
            )

        changed = signature.as_dict()
        changed["signature"] = _b64url(b"\x00" * 64)
        tampered = approval_signature_from_document(changed)
        with self.assertRaises(SignedApprovalError):
            verify_signed_risk_acceptances(
                self.batch,
                (self.review,),
                (self.acceptance,),
                (tampered,),
                self.fixture.bundle,
                engagement_id=ENGAGEMENT_ID,
                review_trust_resolution_digest=context,
                as_of=AS_OF,
            )

    def test_report_approval_requires_two_distinct_signed_approvers(self) -> None:
        report = demo_regulatory_report(issued_at=datetime(2026, 8, 13, 10, 0, tzinfo=timezone.utc))
        trusted_body = {
            "schema_version": "finredops.trusted-report-promotion.v1",
            "base_promotion_digest": "1" * 64,
            "report_id": report.report_id,
            "report_digest": report.digest(),
            "engagement_id": ENGAGEMENT_ID,
            "trust_resolution_digest": "2" * 64,
            "trust_bundle_digest": "3" * 64,
            "cryptographic_signatures_verified": True,
            "signature_algorithm": "Ed25519",
            "report_issued": False,
            "human_approval_required": True,
        }
        manifest = {**trusted_body, "trusted_promotion_digest": sha256_digest(trusted_body)}
        first = self._report_signature(report, manifest, "approver:risk-committee", "report-key-1", self.fixture.approver1_key)
        second = self._report_signature(report, manifest, "approver:security-committee", "report-key-2", self.fixture.approver2_key)
        approved, resolution = approve_report_with_signatures(
            report,
            (first, second),
            self.fixture.bundle,
            manifest,
            engagement_id=ENGAGEMENT_ID,
            as_of=AS_OF,
        )
        self.assertEqual(approved.status, ReportStatus.APPROVED)
        self.assertEqual(len(approved.human_approvals), 2)
        self.assertTrue(validate_report(approved).ready_for_issue)
        self.assertFalse(resolution.as_dict()["report_issued"])
        self.assertEqual(resolution.source_report_digest, report.digest())

        with self.assertRaises(SignedApprovalError):
            approve_report_with_signatures(
                report,
                (first,),
                self.fixture.bundle,
                manifest,
                engagement_id=ENGAGEMENT_ID,
                as_of=AS_OF,
            )

    def test_signed_approval_commands_are_visible_in_top_level_help(self) -> None:
        captured = StringIO()
        with redirect_stdout(captured):
            self.assertEqual(entrypoint(["--help"]), 0)
        text = captured.getvalue()
        self.assertIn("risk-acceptance-signature-request", text)
        self.assertIn("approve-trusted-report", text)

    def test_trusted_promotion_rejects_unsigned_risk_acceptance(self) -> None:
        second = review_from_draft(
            _false_positive_draft(self.batch, 1, "2026-08-12T09:05:00Z"), self.batch
        )
        reviewer_key = Ed25519PrivateKey.generate()
        reviewer_public = _public(reviewer_key)
        reviewer_bundle_doc = {
            "schema_version": "finredops.reviewer-trust-bundle.v1",
            "bundle_id": "reviewer-trust",
            "keys": [
                {
                    "issuer": "review-idp.example.test",
                    "key_id": "reviewer-key",
                    "algorithm": "Ed25519",
                    "public_key": reviewer_public,
                    "roles": ["qualified_tester"],
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-12-31T23:59:59Z",
                }
            ],
        }
        reviewer_bundle = trust_bundle_from_document(reviewer_bundle_doc)

        def assertion(review):
            request = identity_assertion_signing_document(
                {
                    "issuer": "review-idp.example.test",
                    "subject": review.reviewer_id,
                    "key_id": "reviewer-key",
                    "algorithm": "Ed25519",
                    "purpose": "finding_review",
                    "role": "qualified_tester",
                    "engagement_id": ENGAGEMENT_ID,
                    "batch_id": self.batch.batch_id,
                    "batch_digest": self.batch.digest(),
                    "finding_id": review.finding_id,
                    "object_id": review.review_id,
                    "object_digest": review.digest(),
                    "issued_at": "2026-08-13T10:00:00Z",
                    "expires_at": "2026-08-13T12:00:00Z",
                }
            )
            return identity_assertion_from_document(
                {**request, "signature": _b64url(reviewer_key.sign(_canonical(request)))}
            )

        assertions = (assertion(self.review), assertion(second))
        trust_resolution = resolve_trusted_reviews(
            self.batch,
            (self.review, second),
            (),
            assertions,
            reviewer_bundle,
            engagement_id=ENGAGEMENT_ID,
            as_of=AS_OF,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "intake.json"
            review1 = root / "review1.json"
            review2 = root / "review2.json"
            assertion1 = root / "assertion1.json"
            assertion2 = root / "assertion2.json"
            reviewer_bundle_path = root / "reviewer-bundle.json"
            acceptance = root / "acceptance.json"
            spec = root / "spec.json"
            output = root / "output"
            intake.write_text(json.dumps(self.batch.as_dict()), encoding="utf-8")
            review1.write_text(json.dumps(self.review.as_dict()), encoding="utf-8")
            review2.write_text(json.dumps(second.as_dict()), encoding="utf-8")
            assertion1.write_text(json.dumps(assertions[0].as_dict()), encoding="utf-8")
            assertion2.write_text(json.dumps(assertions[1].as_dict()), encoding="utf-8")
            reviewer_bundle_path.write_text(json.dumps(reviewer_bundle_doc), encoding="utf-8")
            acceptance.write_text(json.dumps(self.acceptance.as_dict()), encoding="utf-8")
            spec.write_text(
                json.dumps(
                    {
                        "schema_version": "finredops.reviewed-report-spec.v1",
                        "report_id": "FRX-RPT-SIGNED-RISK-001",
                        "title": "Synthetic signed-risk report",
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
                        "methodology": ["bounded SARIF", "signed qualified review", "signed risk acceptance"],
                        "executive_summary": "Synthetic signed risk acceptance workflow validation.",
                        "limitations": ["Synthetic evidence only."],
                        "finding_metadata": {
                            self.review.finding_id: {
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
                "--trust-bundle", str(reviewer_bundle_path),
                "--engagement-id", ENGAGEMENT_ID,
                "--as-of", "2026-08-13T11:00:00Z",
                "--acceptance", str(acceptance),
                "--spec", str(spec),
                "--output-dir", str(output),
            ]
            captured = StringIO()
            with redirect_stdout(captured):
                result = entrypoint(args)
            self.assertEqual(result, 1)
            self.assertIn("approval-trust-bundle", captured.getvalue())
            self.assertTrue(trust_resolution.as_dict()["cryptographic_signatures_verified"])


if __name__ == "__main__":
    unittest.main()
