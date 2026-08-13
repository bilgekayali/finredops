from __future__ import annotations

import base64
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from finredops.entrypoint import entrypoint
from finredops.models import sha256_digest
from finredops.oidc_identity import (
    OIDCIdentityError,
    bind_oidc_identity,
    provider_config_from_document,
    resolve_oidc_workflow_bindings,
    verify_oidc_id_token,
)
from finredops.signed_approvals import approval_signature_request
from finredops.trust import identity_assertion_signing_document

AS_OF = datetime(2026, 8, 13, 8, 0, 0, tzinfo=timezone.utc)
ISSUER = "https://idp.example.test"
CLIENT_ID = "finredops-regulated-client"
KID = "oidc-signing-key-2026"
NONCE = "synthetic-nonce-2026-08-13"
ENGAGEMENT = "FRX-DEMO-2026-001"
SUBJECT = "tester:bilge-kayali"
ACR = "urn:example:mfa"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class OIDCFixture:
    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        self.jwks = {"keys": [jwk]}
        self.provider_document = {
            "schema_version": "finredops.oidc-provider.v1",
            "provider_id": "synthetic-bank-idp",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "allowed_algorithms": ["RS256"],
            "role_claim": "roles",
            "required_acr": [ACR],
            "max_auth_age_seconds": 3600,
            "max_token_lifetime_seconds": 3600,
            "clock_skew_seconds": 60,
        }
        self.config = provider_config_from_document(self.provider_document)

    def token(
        self,
        *,
        nonce: str = NONCE,
        audience: str = CLIENT_ID,
        subject: str = SUBJECT,
        roles: list[str] | None = None,
        algorithm: str = "RS256",
        auth_time: int | None = None,
        kid: str = KID,
    ) -> str:
        now = int(AS_OF.timestamp())
        payload = {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": now - 300,
            "exp": now + 600,
            "auth_time": now - 240 if auth_time is None else auth_time,
            "nonce": nonce,
            "acr": ACR,
            "roles": roles or ["qualified_tester", "report_approver"],
        }
        return jwt.encode(payload, self.private_key, algorithm=algorithm, headers={"kid": kid, "typ": "JWT"})

    def reviewer_assertion(self, *, subject: str = SUBJECT, role: str = "qualified_tester") -> dict[str, object]:
        core = identity_assertion_signing_document(
            {
                "issuer": "review-trust.example.test",
                "subject": subject,
                "key_id": "review-key-2026",
                "algorithm": "Ed25519",
                "purpose": "finding_review" if role == "qualified_tester" else "review_lifecycle",
                "role": role,
                "engagement_id": ENGAGEMENT,
                "batch_id": "FRX-BATCH-SYNTHETIC",
                "batch_digest": "a" * 64,
                "finding_id": "FRX-SYN-001",
                "object_id": "FRX-REV-0123456789ABCDEF01234567" if role == "qualified_tester" else "FRX-RLC-0123456789ABCDEF01234567",
                "object_digest": "b" * 64,
                "issued_at": "2026-08-13T07:45:00Z",
                "expires_at": "2026-08-13T08:30:00Z",
            }
        )
        return {**core, "signature": _b64url(b"\x01" * 64)}

    def approval_signature(self, *, subject: str = SUBJECT, role: str = "report_approver") -> dict[str, object]:
        purpose = "report_approval" if role == "report_approver" else "risk_acceptance"
        object_type = "regulatory_report" if role == "report_approver" else "risk_acceptance"
        request = approval_signature_request(
            {
                "issuer": "approval-trust.example.test",
                "subject": subject,
                "key_id": "approval-key-2026",
                "algorithm": "Ed25519",
                "purpose": purpose,
                "role": role,
                "engagement_id": ENGAGEMENT,
                "object_type": object_type,
                "object_id": "FRX-RPT-SYN-001" if role == "report_approver" else "FRX-RISK-0123456789ABCDEF01234567",
                "object_digest": "c" * 64,
                "context_digest": "d" * 64,
                "issued_at": "2026-08-13T07:45:00Z",
                "expires_at": "2026-08-13T08:30:00Z",
            }
        )
        return {**request, "signature": _b64url(b"\x02" * 64)}


class OIDCIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = OIDCFixture()

    def test_valid_oidc_id_token_is_verified_without_retaining_raw_token(self) -> None:
        token = self.fixture.token()
        result = verify_oidc_id_token(
            token,
            self.fixture.config,
            self.fixture.jwks,
            expected_nonce=NONCE,
            as_of=AS_OF,
        )
        document = result.as_dict()
        self.assertEqual(result.subject, SUBJECT)
        self.assertEqual(result.roles, ("qualified_tester", "report_approver"))
        self.assertTrue(document["external_idp_protocol_verified"])
        self.assertFalse(document["raw_id_token_retained"])
        self.assertNotIn(token, json.dumps(document))

    def test_algorithm_nonce_key_and_auth_age_fail_closed(self) -> None:
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(algorithm="PS256"),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(nonce="other-nonce"),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(kid="unknown-key"),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(auth_time=int(AS_OF.timestamp()) - 7200),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )

    def test_audience_acr_and_role_claims_are_pinned(self) -> None:
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(audience="other-client"),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )
        with self.assertRaises(OIDCIdentityError):
            verify_oidc_id_token(
                self.fixture.token(roles=["unrelated-role"]),
                self.fixture.config,
                self.fixture.jwks,
                expected_nonce=NONCE,
                as_of=AS_OF,
            )

    def test_oidc_subject_and_role_bind_to_signed_finredops_objects(self) -> None:
        verification = verify_oidc_id_token(
            self.fixture.token(), self.fixture.config, self.fixture.jwks,
            expected_nonce=NONCE, as_of=AS_OF,
        )
        reviewer = self.fixture.reviewer_assertion()
        approval = self.fixture.approval_signature()
        reviewer_binding = bind_oidc_identity(verification, reviewer, as_of=AS_OF)
        approval_binding = bind_oidc_identity(verification, approval, as_of=AS_OF)
        self.assertEqual(reviewer_binding.role, "qualified_tester")
        self.assertEqual(approval_binding.role, "report_approver")

        mismatch = self.fixture.reviewer_assertion(subject="tester:someone-else")
        with self.assertRaises(OIDCIdentityError):
            bind_oidc_identity(verification, mismatch, as_of=AS_OF)

    def test_workflow_resolution_requires_exact_binding_coverage(self) -> None:
        verification = verify_oidc_id_token(
            self.fixture.token(), self.fixture.config, self.fixture.jwks,
            expected_nonce=NONCE, as_of=AS_OF,
        )
        reviewer = self.fixture.reviewer_assertion()
        approval = self.fixture.approval_signature()
        bindings = (
            bind_oidc_identity(verification, reviewer, as_of=AS_OF),
            bind_oidc_identity(verification, approval, as_of=AS_OF),
        )
        resolution = resolve_oidc_workflow_bindings(
            bindings, (reviewer, approval), engagement_id=ENGAGEMENT
        )
        self.assertTrue(resolution.as_dict()["external_idp_protocol_verified"])
        self.assertTrue(resolution.as_dict()["exact_binding_coverage"])
        with self.assertRaises(OIDCIdentityError):
            resolve_oidc_workflow_bindings(
                bindings[:1], (reviewer, approval), engagement_id=ENGAGEMENT
            )

    def test_cli_verifies_token_and_writes_minimized_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider = root / "provider.json"
            jwks = root / "jwks.json"
            token = root / "id-token.jwt"
            output = root / "verification.json"
            provider.write_text(json.dumps(self.fixture.provider_document), encoding="utf-8")
            jwks.write_text(json.dumps(self.fixture.jwks), encoding="utf-8")
            raw = self.fixture.token()
            token.write_text(raw + "\n", encoding="utf-8")
            captured = StringIO()
            with redirect_stdout(captured):
                result = entrypoint(
                    [
                        "verify-oidc-id-token",
                        "--provider-config", str(provider),
                        "--jwks", str(jwks),
                        "--id-token", str(token),
                        "--expected-nonce", NONCE,
                        "--as-of", "2026-08-13T08:00:00Z",
                        "--output", str(output),
                    ]
                )
            self.assertEqual(result, 0, captured.getvalue())
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(artifact["external_idp_protocol_verified"])
            self.assertEqual(artifact["token_digest"], __import__("hashlib").sha256(raw.encode()).hexdigest())
            self.assertNotIn(raw, output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
