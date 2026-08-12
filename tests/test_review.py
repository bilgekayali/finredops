from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from finredops.cli import entrypoint
from finredops.intake import EvidenceIntakeBatch, import_sarif_file
from finredops.regulations import AssessmentType
from finredops.review import (
    ReviewDisposition,
    ReviewDocumentError,
    ReviewOutcome,
    RiskAcceptanceStatus,
    build_review_summary,
    read_review_json,
    review_from_document,
    review_from_draft,
    review_summary_from_document,
    review_template_document,
    risk_acceptance_from_document,
    risk_acceptance_from_draft,
    risk_acceptance_template_document,
)


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"
ASSESSMENT_TYPE = AssessmentType.VENDOR_SOURCE_CODE_REVIEW


def confirmed_draft(
    batch: EvidenceIntakeBatch,
    finding_index: int = 0,
    *,
    reviewer_id: str = "tester:bilge-kayali",
) -> dict[str, object]:
    finding = batch.findings[finding_index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT_TYPE)
    document.update(
        {
            "disposition": "confirmed",
            "reviewer_id": reviewer_id,
            "qualification_evidence_ref": (
                "qualification-evidence://person/tester-bilge/current"
            ),
            "reviewed_at": "2026-08-12T09:00:00Z",
            "rationale": (
                "The qualified tester reproduced the synthetic condition and "
                "correlated the result with the retained evidence record."
            ),
            "validation_evidence_refs": [
                f"evidence://review/{finding.fingerprint}"
            ],
            "final_severity": finding.machine_severity.value,
            "business_impact": (
                "The synthetic condition could weaken the tested security boundary "
                "if it were present in an authorized target."
            ),
            "recommendation": (
                "Apply the documented defensive control and perform an independent "
                "retest before closing the finding."
            ),
            "control_refs": ["TR-BDDK-BSEBY-22-4-5"],
        }
    )
    return document


def false_positive_draft(
    batch: EvidenceIntakeBatch, finding_index: int = 0
) -> dict[str, object]:
    finding = batch.findings[finding_index]
    document = review_template_document(batch, finding.finding_id, ASSESSMENT_TYPE)
    document.update(
        {
            "disposition": "false_positive",
            "reviewer_id": "tester:bilge-kayali",
            "qualification_evidence_ref": (
                "qualification-evidence://person/tester-bilge/current"
            ),
            "reviewed_at": "2026-08-12T09:00:00Z",
            "rationale": (
                "The qualified tester inspected the synthetic evidence and confirmed "
                "that the reported condition is not present."
            ),
            "validation_evidence_refs": [
                f"evidence://review/{finding.fingerprint}"
            ],
        }
    )
    return document


def acceptance_draft(review: object) -> dict[str, object]:
    document = risk_acceptance_template_document(review)  # type: ignore[arg-type]
    document.update(
        {
            "accepted_by": "risk-owner:payments",
            "approved_at": "2026-08-13T10:00:00Z",
            "expires_on": "2027-02-13",
            "approval_evidence_ref": "attachment://approvals/RISK-2026-0042",
            "rationale": (
                "The accountable business owner accepts the documented residual risk "
                "until the approved remediation date."
            ),
            "compensating_controls": [
                "Daily monitoring and restricted access remain active until remediation."
            ],
        }
    )
    return document


class FindingReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.batch = import_sarif_file(SYNTHETIC_SARIF)

    def test_confirmed_review_is_digest_bound_and_round_trips(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        self.assertEqual(review.disposition, ReviewDisposition.CONFIRMED)
        self.assertTrue(review.review_id.startswith("FRX-REV-"))
        self.assertFalse(review.as_dict()["cryptographic_signature_present"])
        loaded = review_from_document(review.as_dict(), self.batch)
        self.assertEqual(loaded, review)

    def test_review_digest_and_intake_binding_detect_tampering(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        changed = copy.deepcopy(review.as_dict())
        changed["rationale"] = changed["rationale"] + " Altered."
        with self.assertRaises(ValueError):
            review_from_document(changed, self.batch)

        changed_batch = copy.deepcopy(confirmed_draft(self.batch))
        changed_batch["batch_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            review_from_draft(changed_batch, self.batch)

        changed_profile = confirmed_draft(self.batch)
        changed_profile["control_profile_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            review_from_draft(changed_profile, self.batch)

    def test_unknown_control_sensitive_text_and_placeholders_fail_closed(self) -> None:
        unknown_control = confirmed_draft(self.batch)
        unknown_control["control_refs"] = ["UNREGISTERED-CONTROL"]
        with self.assertRaises(ValueError):
            review_from_draft(unknown_control, self.batch)

        wrong_assessment = confirmed_draft(self.batch)
        wrong_assessment["assessment_type"] = "annual_bank_penetration"
        with self.assertRaises(ValueError):
            review_from_draft(wrong_assessment, self.batch)

        sensitive = confirmed_draft(self.batch)
        sensitive["rationale"] = (
            "The result was reviewed for customer@example.com and must remain "
            "outside this metadata-only decision record."
        )
        with self.assertRaises(ReviewDocumentError):
            review_from_draft(sensitive, self.batch)

        placeholder = confirmed_draft(self.batch)
        placeholder["reviewer_id"] = "TODO"
        with self.assertRaises(ReviewDocumentError):
            review_from_draft(placeholder, self.batch)

    def test_severity_override_requires_substantive_reason(self) -> None:
        document = confirmed_draft(self.batch)
        original = document["final_severity"]
        document["final_severity"] = "critical" if original != "critical" else "low"
        with self.assertRaises(ValueError):
            review_from_draft(document, self.batch)
        document["severity_override_reason"] = (
            "Validated exploitability and financial process exposure justify the "
            "human severity override."
        )
        review = review_from_draft(document, self.batch)
        self.assertEqual(review.final_severity.value, document["final_severity"])

    def test_non_confirmed_disposition_cannot_carry_report_conclusions(self) -> None:
        document = false_positive_draft(self.batch)
        document["business_impact"] = "This should never be accepted as final impact text."
        with self.assertRaises(ValueError):
            review_from_draft(document, self.batch)

    def test_duplicate_requires_a_confirmed_primary_and_rejects_chains(self) -> None:
        primary = review_from_draft(confirmed_draft(self.batch, 0), self.batch)
        duplicate_document = false_positive_draft(self.batch, 1)
        duplicate_document.update(
            {
                "disposition": "duplicate",
                "duplicate_of": primary.finding_id,
                "rationale": (
                    "The tester correlated the fingerprint and evidence with the "
                    "confirmed primary finding in this intake."
                ),
            }
        )
        duplicate = review_from_draft(duplicate_document, self.batch)
        summary = build_review_summary(
            self.batch,
            (primary, duplicate),
            assessment_type=ASSESSMENT_TYPE,
            as_of=datetime(2026, 8, 14, tzinfo=timezone.utc),
        )
        self.assertEqual(summary.duplicate_count, 1)
        self.assertTrue(summary.complete)

        false_primary = review_from_draft(false_positive_draft(self.batch, 0), self.batch)
        with self.assertRaises(ValueError):
            build_review_summary(
                self.batch,
                (false_primary, duplicate),
                assessment_type=ASSESSMENT_TYPE,
                as_of=datetime(2026, 8, 14, tzinfo=timezone.utc),
            )

    def test_risk_acceptance_is_separate_time_bound_and_role_separated(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        acceptance = risk_acceptance_from_draft(
            acceptance_draft(review), self.batch, review
        )
        self.assertNotEqual(acceptance.accepted_by, review.reviewer_id)
        self.assertFalse(acceptance.as_dict()["cryptographic_signature_present"])
        loaded = risk_acceptance_from_document(
            acceptance.as_dict(), self.batch, review
        )
        self.assertEqual(loaded, acceptance)

        changed = copy.deepcopy(acceptance.as_dict())
        changed["rationale"] = changed["rationale"] + " Altered."
        with self.assertRaises(ValueError):
            risk_acceptance_from_document(changed, self.batch, review)

        same_person = acceptance_draft(review)
        same_person["accepted_by"] = review.reviewer_id
        with self.assertRaises(ValueError):
            risk_acceptance_from_draft(same_person, self.batch, review)

        too_long = acceptance_draft(review)
        too_long["expires_on"] = "2028-08-13"
        with self.assertRaises(ValueError):
            risk_acceptance_from_draft(too_long, self.batch, review)

        placeholder = acceptance_draft(review)
        placeholder["accepted_by"] = "TODO"
        with self.assertRaises(ReviewDocumentError):
            risk_acceptance_from_draft(placeholder, self.batch, review)

        no_controls = acceptance_draft(review)
        no_controls["compensating_controls"] = []
        with self.assertRaises(ValueError):
            risk_acceptance_from_draft(no_controls, self.batch, review)

    def test_only_confirmed_findings_can_receive_risk_acceptance(self) -> None:
        review = review_from_draft(false_positive_draft(self.batch), self.batch)
        with self.assertRaises(ValueError):
            risk_acceptance_template_document(review)

    def test_summary_distinguishes_active_and_expired_acceptance(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        acceptance = risk_acceptance_from_draft(
            acceptance_draft(review), self.batch, review
        )
        active = build_review_summary(
            self.batch,
            (review,),
            (acceptance,),
            assessment_type=ASSESSMENT_TYPE,
            as_of=datetime(2027, 2, 13, tzinfo=timezone.utc),
        )
        state = next(item for item in active.states if item.review_id)
        self.assertEqual(state.outcome, ReviewOutcome.ACCEPTED_RISK)
        self.assertEqual(state.risk_acceptance_status, RiskAcceptanceStatus.ACTIVE)
        self.assertEqual(active.pending_count, 1)
        self.assertFalse(active.report_promotion_performed)

        expired = build_review_summary(
            self.batch,
            (review,),
            (acceptance,),
            assessment_type=ASSESSMENT_TYPE,
            as_of=datetime(2027, 2, 14, tzinfo=timezone.utc),
        )
        state = next(item for item in expired.states if item.review_id)
        self.assertEqual(state.outcome, ReviewOutcome.CONFIRMED)
        self.assertEqual(state.risk_acceptance_status, RiskAcceptanceStatus.EXPIRED)
        self.assertEqual(expired.expired_risk_acceptance_count, 1)

        with self.assertRaises(ValueError):
            build_review_summary(
                self.batch,
                (review,),
                (acceptance,),
                assessment_type=ASSESSMENT_TYPE,
                as_of=datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
            )

    def test_summary_round_trip_and_tamper_detection(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        summary = build_review_summary(
            self.batch,
            (review,),
            assessment_type=ASSESSMENT_TYPE,
            as_of=datetime(2026, 8, 14, tzinfo=timezone.utc),
        )
        loaded = review_summary_from_document(summary.as_dict(), self.batch)
        self.assertEqual(loaded, summary)
        changed = copy.deepcopy(summary.as_dict())
        changed["pending_count"] = 0
        with self.assertRaises(ValueError):
            review_summary_from_document(changed, self.batch)

    def test_versioned_schema_required_fields_match_final_documents(self) -> None:
        review = review_from_draft(confirmed_draft(self.batch), self.batch)
        acceptance = risk_acceptance_from_draft(
            acceptance_draft(review), self.batch, review
        )
        summary = build_review_summary(
            self.batch,
            (review,),
            (acceptance,),
            assessment_type=ASSESSMENT_TYPE,
            as_of=datetime(2026, 8, 14, tzinfo=timezone.utc),
        )
        contracts = (
            ("finding-review.schema.json", review.as_dict()),
            ("risk-acceptance.schema.json", acceptance.as_dict()),
            ("finding-review-summary.schema.json", summary.as_dict()),
        )
        for schema_name, document in contracts:
            with self.subTest(schema=schema_name):
                schema = json.loads(
                    (ROOT / "schemas" / schema_name).read_text(encoding="utf-8")
                )
                self.assertEqual(set(schema["required"]), set(document))

    def test_bounded_json_reader_rejects_duplicate_nan_and_deep_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(ReviewDocumentError):
                read_review_json(path)
            path.write_text('{"score":NaN}', encoding="utf-8")
            with self.assertRaises(ReviewDocumentError):
                read_review_json(path)
            nested: object = "end"
            for _ in range(40):
                nested = {"child": nested}
            path.write_text(json.dumps(nested), encoding="utf-8")
            with self.assertRaises(ReviewDocumentError):
                read_review_json(path)

    def test_cli_runs_review_acceptance_and_summary_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "intake.json"
            review_draft = root / "review-draft.json"
            review_path = root / "review.json"
            acceptance_draft_path = root / "acceptance-draft.json"
            acceptance_path = root / "acceptance.json"
            summary_path = root / "summary.json"
            finding_id = self.batch.findings[0].finding_id

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    entrypoint(
                        ["import-sarif", str(SYNTHETIC_SARIF), "--output", str(intake)]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "finding-review-template",
                            "--intake",
                            str(intake),
                            "--finding-id",
                            finding_id,
                            "--assessment-type",
                            ASSESSMENT_TYPE.value,
                            "--output",
                            str(review_draft),
                        ]
                    ),
                    0,
                )
                original_draft = review_draft.read_bytes()
                self.assertEqual(
                    entrypoint(
                        [
                            "finding-review-template",
                            "--intake",
                            str(intake),
                            "--finding-id",
                            finding_id,
                            "--assessment-type",
                            ASSESSMENT_TYPE.value,
                            "--output",
                            str(review_draft),
                        ]
                    ),
                    1,
                )
                self.assertEqual(review_draft.read_bytes(), original_draft)
            review_document = json.loads(review_draft.read_text(encoding="utf-8"))
            completed_review = confirmed_draft(self.batch)
            review_document.update(
                {key: value for key, value in completed_review.items() if key != "machine_context"}
            )
            review_draft.write_text(
                json.dumps(review_document), encoding="utf-8"
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    entrypoint(
                        [
                            "finalize-finding-review",
                            "--intake",
                            str(intake),
                            "--draft",
                            str(review_draft),
                            "--output",
                            str(review_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "validate-finding-review",
                            "--intake",
                            str(intake),
                            "--review",
                            str(review_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "risk-acceptance-template",
                            "--intake",
                            str(intake),
                            "--review",
                            str(review_path),
                            "--output",
                            str(acceptance_draft_path),
                        ]
                    ),
                    0,
                )
            review = review_from_document(
                read_review_json(review_path), self.batch
            )
            acceptance_document = json.loads(
                acceptance_draft_path.read_text(encoding="utf-8")
            )
            acceptance_document.update(acceptance_draft(review))
            acceptance_draft_path.write_text(
                json.dumps(acceptance_document), encoding="utf-8"
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    entrypoint(
                        [
                            "finalize-risk-acceptance",
                            "--intake",
                            str(intake),
                            "--review",
                            str(review_path),
                            "--draft",
                            str(acceptance_draft_path),
                            "--output",
                            str(acceptance_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "validate-risk-acceptance",
                            "--intake",
                            str(intake),
                            "--review",
                            str(review_path),
                            "--acceptance",
                            str(acceptance_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "build-review-summary",
                            "--intake",
                            str(intake),
                            "--assessment-type",
                            ASSESSMENT_TYPE.value,
                            "--review",
                            str(review_path),
                            "--acceptance",
                            str(acceptance_path),
                            "--as-of",
                            "2026-08-14T00:00:00Z",
                            "--output",
                            str(summary_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "validate-review-summary",
                            "--intake",
                            str(intake),
                            "--summary",
                            str(summary_path),
                        ]
                    ),
                    1,
                )
                self.assertEqual(
                    entrypoint(
                        [
                            "validate-review-summary",
                            "--intake",
                            str(intake),
                            "--summary",
                            str(summary_path),
                            "--review",
                            str(review_path),
                            "--acceptance",
                            str(acceptance_path),
                        ]
                    ),
                    0,
                )
            summary_document = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertFalse(summary_document["report_promotion_performed"])
            self.assertTrue(summary_document["audit_support_only"])


if __name__ == "__main__":
    unittest.main()
