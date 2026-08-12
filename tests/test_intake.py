from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from finredops.cli import entrypoint
from finredops.intake import (
    MachineSeverity,
    SarifIntakeError,
    import_sarif_document,
    import_sarif_file,
    intake_from_document,
)


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SARIF = ROOT / "examples" / "synthetic_sast.sarif.json"


def minimal_sarif() -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Synthetic Scanner",
                        "version": "1.0",
                        "rules": [
                            {
                                "id": "SYN-001",
                                "shortDescription": {"text": "Synthetic result"},
                                "properties": {
                                    "precision": "high",
                                    "tags": ["CWE-79"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "SYN-001",
                        "ruleIndex": 0,
                        "level": "warning",
                        "message": {"text": "Synthetic observation for review."},
                        "partialFingerprints": {"stable/v1": "abc123"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/example.py"},
                                    "region": {"startLine": 12, "startColumn": 4},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


class SarifIntakeTests(unittest.TestCase):
    def test_synthetic_sarif_is_deduplicated_into_review_candidates(self) -> None:
        batch = import_sarif_file(SYNTHETIC_SARIF)
        self.assertEqual(batch.run_count, 1)
        self.assertEqual(batch.result_count, 3)
        self.assertEqual(len(batch.findings), 2)
        self.assertEqual(batch.duplicate_result_count, 1)
        self.assertEqual(batch.unsafe_location_count, 1)
        self.assertEqual(batch.redacted_result_count, 2)
        self.assertTrue(batch.human_review_required)
        self.assertFalse(batch.raw_source_embedded)
        self.assertTrue(all(item.review_disposition == "pending_review" for item in batch.findings))
        self.assertTrue(all(item.human_validation_required for item in batch.findings))
        merged = next(item for item in batch.findings if item.rule_id == "SYN-SQL-001")
        self.assertEqual(merged.occurrence_count, 2)
        self.assertEqual(merged.machine_severity, MachineSeverity.HIGH)

    def test_import_is_deterministic_for_identical_bytes(self) -> None:
        first = import_sarif_file(SYNTHETIC_SARIF)
        second = import_sarif_file(SYNTHETIC_SARIF)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(first.digest(), second.digest())

    def test_secret_identifiers_and_source_snippets_are_not_exported(self) -> None:
        document = minimal_sarif()
        result = document["runs"][0]["results"][0]  # type: ignore[index]
        access_key_fixture = "AKIA" + "A" * 16
        github_token_fixture = "ghp_" + "B" * 32
        result["message"]["text"] = (  # type: ignore[index]
            "api_key=super-secret-value Bearer abcdefghijklmnop "
            f"owned by reviewer@example.com {access_key_fixture} "
            f"{github_token_fixture}"
        )
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {  # type: ignore[index]
            "text": "password=must-never-be-copied"
        }
        finding = import_sarif_document(document).findings[0]
        rendered = json.dumps(finding.__dict__ if hasattr(finding, "__dict__") else {
            "message": finding.message,
            "redaction_kinds": finding.redaction_kinds,
        })
        self.assertNotIn("super-secret-value", rendered)
        self.assertNotIn("abcdefghijklmnop", rendered)
        self.assertNotIn("reviewer@example.com", rendered)
        self.assertNotIn(access_key_fixture, rendered)
        self.assertNotIn(github_token_fixture, rendered)
        self.assertNotIn("must-never-be-copied", rendered)
        self.assertIn("[REDACTED:SECRET]", finding.message)
        self.assertIn("secret_field", finding.redaction_kinds)
        self.assertIn("bearer_token", finding.redaction_kinds)
        self.assertIn("email", finding.redaction_kinds)

    def test_absolute_and_traversal_locations_become_opaque(self) -> None:
        for location in ("file:///home/operator/private.py", "../../private.py"):
            with self.subTest(location=location):
                document = minimal_sarif()
                result = document["runs"][0]["results"][0]  # type: ignore[index]
                physical = result["locations"][0]["physicalLocation"]  # type: ignore[index]
                physical["artifactLocation"]["uri"] = location
                batch = import_sarif_document(document)
                self.assertEqual(batch.unsafe_location_count, 1)
                self.assertTrue(batch.findings[0].artifact_ref.startswith("artifact-digest://"))
                self.assertNotIn("private.py", batch.findings[0].artifact_ref)

    def test_safe_location_remains_repository_relative(self) -> None:
        finding = import_sarif_document(minimal_sarif()).findings[0]
        self.assertEqual(finding.artifact_ref, "repo://src/example.py")
        self.assertEqual(finding.start_line, 12)

    def test_rule_id_without_index_resolves_the_driver_descriptor(self) -> None:
        document = minimal_sarif()
        result = document["runs"][0]["results"][0]  # type: ignore[index]
        del result["ruleIndex"]
        del result["level"]
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]  # type: ignore[index]
        rule["defaultConfiguration"] = {"level": "error"}
        finding = import_sarif_document(document).findings[0]
        self.assertEqual(finding.title, "Synthetic result")
        self.assertEqual(finding.machine_severity, MachineSeverity.HIGH)

    def test_rule_message_id_resolves_without_copying_arguments(self) -> None:
        document = minimal_sarif()
        result = document["runs"][0]["results"][0]  # type: ignore[index]
        result["message"] = {
            "id": "review-message",
            "arguments": ["password=must-not-be-copied"],
        }
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]  # type: ignore[index]
        rule["messageStrings"] = {
            "review-message": {"text": "Synthetic templated result {0}."}
        }
        batch = import_sarif_document(document)
        finding = batch.findings[0]
        self.assertEqual(finding.message, "Synthetic templated result {0}.")
        self.assertNotIn("must-not-be-copied", json.dumps(batch.as_dict()))

    def test_stable_partial_fingerprint_deduplicates_line_moves(self) -> None:
        document = minimal_sarif()
        original = document["runs"][0]["results"][0]  # type: ignore[index]
        duplicate = copy.deepcopy(original)
        duplicate["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
        duplicate["message"]["text"] = "Same observation after a line move."
        document["runs"][0]["results"].append(duplicate)  # type: ignore[index]
        batch = import_sarif_document(document)
        self.assertEqual(len(batch.findings), 1)
        self.assertEqual(batch.findings[0].occurrence_count, 2)
        self.assertEqual(batch.findings[0].start_line, 12)

    def test_merged_candidate_is_independent_of_result_order(self) -> None:
        document = minimal_sarif()
        original = document["runs"][0]["results"][0]  # type: ignore[index]
        duplicate = copy.deepcopy(original)
        duplicate["level"] = "error"
        duplicate["message"]["text"] = "Another normalized description."
        document["runs"][0]["results"].append(duplicate)  # type: ignore[index]
        reversed_document = copy.deepcopy(document)
        reversed_document["runs"][0]["results"].reverse()  # type: ignore[index]
        digest = "a" * 64
        first = import_sarif_document(
            document, source_content_sha256=digest, source_size_bytes=1_000
        )
        second = import_sarif_document(
            reversed_document, source_content_sha256=digest, source_size_bytes=1_000
        )
        self.assertEqual(first.as_dict(), second.as_dict())

    def test_invalid_version_and_rule_mismatch_fail_closed(self) -> None:
        wrong_version = minimal_sarif()
        wrong_version["version"] = "2.0.0"
        with self.assertRaises(SarifIntakeError):
            import_sarif_document(wrong_version)

        mismatch = minimal_sarif()
        mismatch["runs"][0]["results"][0]["ruleId"] = "OTHER"  # type: ignore[index]
        with self.assertRaises(SarifIntakeError):
            import_sarif_document(mismatch)

        duplicate_rule = minimal_sarif()
        rules = duplicate_rule["runs"][0]["tool"]["driver"]["rules"]  # type: ignore[index]
        rules.append(copy.deepcopy(rules[0]))
        with self.assertRaises(SarifIntakeError):
            import_sarif_document(duplicate_rule)

    def test_result_limit_and_invalid_positions_fail_closed(self) -> None:
        document = minimal_sarif()
        with self.assertRaises(ValueError):
            import_sarif_document(document, maximum_results=0)
        result = document["runs"][0]["results"][0]  # type: ignore[index]
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = True
        with self.assertRaises(SarifIntakeError):
            import_sarif_document(document)

    def test_export_round_trip_and_digest_tampering_detection(self) -> None:
        document = import_sarif_file(SYNTHETIC_SARIF).as_dict()
        loaded = intake_from_document(document)
        self.assertEqual(loaded.as_dict(), document)

        changed = copy.deepcopy(document)
        changed["findings"][0]["message"] = "Changed after digest"
        with self.assertRaises(SarifIntakeError):
            intake_from_document(changed)

        unknown = copy.deepcopy(document)
        unknown["raw_results"] = []
        with self.assertRaises(SarifIntakeError):
            intake_from_document(unknown)

    def test_boolean_review_boundary_is_strict(self) -> None:
        document = import_sarif_file(SYNTHETIC_SARIF).as_dict()
        document["human_review_required"] = 1
        with self.assertRaises(SarifIntakeError):
            intake_from_document(document)

    def test_file_size_and_utf8_boundaries_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.sarif"
            path.write_text("{}" * 100, encoding="utf-8")
            with self.assertRaises(SarifIntakeError):
                import_sarif_file(path, maximum_bytes=10)
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(SarifIntakeError):
                import_sarif_file(path)

    def test_duplicate_keys_non_finite_numbers_and_deep_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.sarif"
            path.write_text(
                '{"version":"2.1.0","version":"2.1.0","runs":[]}',
                encoding="utf-8",
            )
            with self.assertRaises(SarifIntakeError):
                import_sarif_file(path)
            path.write_text(
                '{"version":"2.1.0","runs":[],"score":NaN}',
                encoding="utf-8",
            )
            with self.assertRaises(SarifIntakeError):
                import_sarif_file(path)

        document = minimal_sarif()
        nested: dict[str, object] = {}
        document["ignored"] = nested
        for _ in range(70):
            child: dict[str, object] = {}
            nested["child"] = child
            nested = child
        with self.assertRaises(SarifIntakeError):
            import_sarif_document(document)

    def test_cli_imports_and_validates_without_printing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "intake.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = entrypoint(
                    ["import-sarif", str(SYNTHETIC_SARIF), "--output", str(output)]
                )
            self.assertEqual(result, 0)
            self.assertTrue(output.is_file())
            self.assertNotIn("synthetic-not-a-real-secret", stdout.getvalue())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(entrypoint(["validate-intake", str(output)]), 0)

    def test_cli_refuses_to_overwrite_the_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.sarif"
            original = SYNTHETIC_SARIF.read_bytes()
            source.write_bytes(original)
            with redirect_stdout(io.StringIO()):
                result = entrypoint(
                    ["import-sarif", str(source), "--output", str(source)]
                )
            self.assertEqual(result, 1)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
