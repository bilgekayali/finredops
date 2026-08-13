from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from finredops.entrypoint import entrypoint
from finredops.institution import (
    InstitutionContextError,
    InstitutionKeyReference,
    InstitutionSecurityContext,
    institution_context_from_document,
    institution_context_template,
)


class InstitutionContextTests(unittest.TestCase):
    def test_template_is_digest_bound_and_contains_no_secret_material(self) -> None:
        document = institution_context_template()
        context = institution_context_from_document(document)
        self.assertEqual(context.institution_id, "example-bank")
        self.assertEqual(context.active_key("data_encryption").purpose, "data_encryption")
        self.assertEqual(context.active_key("audit_signing").purpose, "audit_signing")
        self.assertEqual(document["context_digest"], context.digest())
        self.assertNotIn("PRIVATE KEY", json.dumps(document).upper())

    def test_private_key_material_is_rejected_as_reference(self) -> None:
        with self.assertRaises(InstitutionContextError):
            InstitutionKeyReference(
                key_id="bad-key",
                purpose="audit_signing",
                provider="external_hsm",
                key_ref="-----BEGIN PRIVATE KEY-----abc",
            )

    def test_tampered_context_digest_is_rejected(self) -> None:
        document = institution_context_template()
        document["context_digest"] = "f" * 64
        with self.assertRaises(InstitutionContextError):
            institution_context_from_document(document)

    def test_non_boolean_institution_owned_is_rejected_without_coercion(self) -> None:
        document = institution_context_template()
        document["key_references"][0]["institution_owned"] = "true"
        with self.assertRaises(InstitutionContextError):
            institution_context_from_document(document)

    def test_multiple_active_keys_for_same_purpose_are_rejected(self) -> None:
        data_a = InstitutionKeyReference(
            key_id="data-a",
            purpose="data_encryption",
            provider="other",
            key_ref="kms-ref-a",
        )
        data_b = InstitutionKeyReference(
            key_id="data-b",
            purpose="data_encryption",
            provider="other",
            key_ref="kms-ref-b",
        )
        audit = InstitutionKeyReference(
            key_id="audit",
            purpose="audit_signing",
            provider="other",
            key_ref="hsm-ref",
        )
        with self.assertRaises(InstitutionContextError):
            InstitutionSecurityContext(
                institution_id="bank-a",
                institution_name="Bank A",
                key_references=(data_a, data_b, audit),
            )

    def test_validation_cli_reports_non_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "institution.json"
            path.write_text(
                json.dumps(institution_context_template()), encoding="utf-8"
            )
            output = StringIO()
            with redirect_stdout(output):
                result = entrypoint(["validate-institution-context", str(path)])
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["valid"])
            self.assertFalse(payload["secret_material_stored"])
            self.assertFalse(payload["encryption_at_rest_verified"])
            self.assertFalse(payload["audit_signature_verified"])


if __name__ == "__main__":
    unittest.main()
