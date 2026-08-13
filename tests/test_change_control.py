from __future__ import annotations

import base64
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finredops.change_control import (
    ChangeControlError,
    ChangeTrustBundle,
    ChangeTrustKey,
    PostgresServiceAccountChange,
    approved_change_package,
    change_signature_request,
    finalize_change_signature,
    postgres_service_account_change_request,
    postgres_service_account_disable_request,
    tenant_policy_change_request,
    verify_approved_change_package,
    verify_postgres_disable_change_package,
    verify_postgres_mapping_change_package,
    verify_tenant_policy_change_package,
)
from finredops.entrypoint import entrypoint
from finredops.institution import InstitutionKeyReference, InstitutionSecurityContext
from finredops.postgres_rls import PostgresRLSContract
from finredops.tenant_auth import TenantRoutingPolicy, TenantSubjectGrant

NOW = datetime(2026, 8, 13, 11, 30, tzinfo=timezone.utc)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public(private: Ed25519PrivateKey) -> str:
    return _b64(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _context() -> InstitutionSecurityContext:
    return InstitutionSecurityContext(
        institution_id="bank-a",
        institution_name="Bank A",
        key_references=(
            InstitutionKeyReference(
                key_id="data-current",
                purpose="data_encryption",
                provider="other",
                key_ref="bank-a/data/current",
            ),
            InstitutionKeyReference(
                key_id="audit-current",
                purpose="audit_signing",
                provider="other",
                key_ref="bank-a/audit/current",
            ),
        ),
    )


def _policy(capabilities=("store_read", "audit_verify")) -> TenantRoutingPolicy:
    return TenantRoutingPolicy(
        policy_id="bank-a-routing-v2",
        institution_id="bank-a",
        oidc_provider_id="bank-idp",
        oidc_provider_config_digest="1" * 64,
        grants=(
            TenantSubjectGrant(
                subject="user-123",
                roles=("qualified_tester", "review_governor"),
                capabilities=capabilities,
            ),
        ),
    )


class ChangeControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config_private = Ed25519PrivateKey.generate()
        self.security_private = Ed25519PrivateKey.generate()
        self.bundle = ChangeTrustBundle(
            bundle_id="bank-a-change-trust-v1",
            keys=(
                ChangeTrustKey(
                    issuer="bank-a-change-ca",
                    subject="config-governor-user",
                    key_id="config-2026",
                    public_key=_public(self.config_private),
                    role="configuration_governor",
                    not_before=NOW - timedelta(days=1),
                    not_after=NOW + timedelta(days=365),
                ),
                ChangeTrustKey(
                    issuer="bank-a-change-ca",
                    subject="security-governor-user",
                    key_id="security-2026",
                    public_key=_public(self.security_private),
                    role="security_governor",
                    not_before=NOW - timedelta(days=1),
                    not_after=NOW + timedelta(days=365),
                ),
            ),
        )

    def _sign(self, request, *, role: str, subject: str):
        if role == "configuration_governor":
            private = self.config_private
            key_id = "config-2026"
        else:
            private = self.security_private
            key_id = "security-2026"
        signing = change_signature_request(
            request,
            issuer="bank-a-change-ca",
            subject=subject,
            key_id=key_id,
            role=role,
            issued_at=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=45),
        )
        payload = json.dumps(
            signing,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return finalize_change_signature(signing, _b64(private.sign(payload)))

    def _tenant_request(self, policy=None):
        return tenant_policy_change_request(
            policy or _policy(),
            _context(),
            operation="create",
            prior_policy_digest=None,
            requested_by="platform-owner",
            reason="Introduce independently governed tenant routing policy.",
            requested_at=NOW,
            valid_until=NOW + timedelta(hours=2),
        )

    def _approved(self, request):
        signatures = (
            self._sign(
                request,
                role="configuration_governor",
                subject="config-governor-user",
            ),
            self._sign(
                request,
                role="security_governor",
                subject="security-governor-user",
            ),
        )
        return approved_change_package(
            request,
            signatures,
            self.bundle,
            approved_at=NOW + timedelta(minutes=5),
        )

    def test_tenant_policy_requires_two_distinct_signed_governors(self) -> None:
        policy = _policy()
        request = self._tenant_request(policy)
        package = self._approved(request)
        restored = verify_approved_change_package(package, self.bundle)
        self.assertEqual(restored.change_id, request.change_id)
        verified = verify_tenant_policy_change_package(
            policy,
            _context(),
            package,
            self.bundle,
        )
        self.assertEqual(verified.after_digest, policy.digest())
        self.assertTrue(package["resolution"]["independent_change_approval_verified"])
        self.assertEqual(
            set(package["resolution"]["roles"]),
            {"configuration_governor", "security_governor"},
        )

    def test_missing_second_signature_fails_closed(self) -> None:
        request = self._tenant_request()
        signature = self._sign(
            request,
            role="configuration_governor",
            subject="config-governor-user",
        )
        with self.assertRaises(ChangeControlError):
            approved_change_package(
                request,
                (signature,),
                self.bundle,
                approved_at=NOW + timedelta(minutes=5),
            )

    def test_signature_subject_must_match_trust_pinned_subject(self) -> None:
        request = self._tenant_request()
        wrong_subject_signature = self._sign(
            request,
            role="configuration_governor",
            subject="different-user",
        )
        valid_security = self._sign(
            request,
            role="security_governor",
            subject="security-governor-user",
        )
        with self.assertRaises(ChangeControlError):
            approved_change_package(
                request,
                (wrong_subject_signature, valid_security),
                self.bundle,
                approved_at=NOW + timedelta(minutes=5),
            )

    def test_bundle_rejects_reused_public_key_under_multiple_identities(self) -> None:
        shared = _public(self.config_private)
        with self.assertRaises(ChangeControlError):
            ChangeTrustBundle(
                bundle_id="unsafe-shared-key-bundle",
                keys=(
                    ChangeTrustKey(
                        issuer="bank-a-change-ca",
                        subject="config-governor-user",
                        key_id="config-shared",
                        public_key=shared,
                        role="configuration_governor",
                        not_before=NOW - timedelta(days=1),
                        not_after=NOW + timedelta(days=1),
                    ),
                    ChangeTrustKey(
                        issuer="bank-a-change-ca",
                        subject="security-governor-user",
                        key_id="security-shared",
                        public_key=shared,
                        role="security_governor",
                        not_before=NOW - timedelta(days=1),
                        not_after=NOW + timedelta(days=1),
                    ),
                ),
            )

    def test_tampered_or_different_tenant_policy_is_not_covered(self) -> None:
        original = _policy()
        package = self._approved(self._tenant_request(original))
        changed = _policy(("store_read", "store_write", "audit_verify"))
        with self.assertRaises(ChangeControlError):
            verify_tenant_policy_change_package(
                changed,
                _context(),
                package,
                self.bundle,
            )

    def test_package_is_bound_to_exact_change_trust_bundle(self) -> None:
        package = self._approved(self._tenant_request())
        other_config = Ed25519PrivateKey.generate()
        other_security = Ed25519PrivateKey.generate()
        other_bundle = ChangeTrustBundle(
            bundle_id="other-change-trust",
            keys=(
                ChangeTrustKey(
                    issuer="other-ca",
                    subject="other-config-user",
                    key_id="config",
                    public_key=_public(other_config),
                    role="configuration_governor",
                    not_before=NOW - timedelta(days=1),
                    not_after=NOW + timedelta(days=1),
                ),
                ChangeTrustKey(
                    issuer="other-ca",
                    subject="other-security-user",
                    key_id="security",
                    public_key=_public(other_security),
                    role="security_governor",
                    not_before=NOW - timedelta(days=1),
                    not_after=NOW + timedelta(days=1),
                ),
            ),
        )
        with self.assertRaises(ChangeControlError):
            verify_approved_change_package(package, other_bundle)

    def test_postgres_mapping_approval_binds_role_tenant_access_and_contract(self) -> None:
        contract = PostgresRLSContract()
        mapping = PostgresServiceAccountChange(
            service_role="bank_a_writer",
            institution_id="bank-a",
            access_mode="write",
            contract_digest=contract.as_dict()["contract_digest"],
        )
        request = postgres_service_account_change_request(
            mapping,
            operation="create",
            prior_mapping_digest=None,
            requested_by="database-platform-owner",
            reason="Provision isolated write service identity.",
            requested_at=NOW,
            valid_until=NOW + timedelta(hours=2),
        )
        package = self._approved(request)
        verify_postgres_mapping_change_package(mapping, package, self.bundle)
        changed_access = PostgresServiceAccountChange(
            service_role="bank_a_writer",
            institution_id="bank-a",
            access_mode="read",
            contract_digest=contract.as_dict()["contract_digest"],
        )
        with self.assertRaises(ChangeControlError):
            verify_postgres_mapping_change_package(changed_access, package, self.bundle)

    def test_postgres_disable_request_is_exact_mapping_state_transition(self) -> None:
        contract_digest = PostgresRLSContract().as_dict()["contract_digest"]
        request = postgres_service_account_disable_request(
            service_role="bank_a_writer",
            institution_id="bank-a",
            contract_digest=contract_digest,
            prior_mapping_digest="7" * 64,
            requested_by="database-platform-owner",
            reason="Retire service account after workload migration.",
            requested_at=NOW,
            valid_until=NOW + timedelta(hours=2),
        )
        package = self._approved(request)
        verified = verify_postgres_disable_change_package(
            service_role="bank_a_writer",
            institution_id="bank-a",
            contract_digest=contract_digest,
            package=package,
            bundle=self.bundle,
        )
        self.assertEqual(verified.before_digest, "7" * 64)
        self.assertIsNone(verified.after_digest)

    def test_update_requires_prior_digest_and_distinct_target(self) -> None:
        with self.assertRaises(ChangeControlError):
            tenant_policy_change_request(
                _policy(),
                _context(),
                operation="update",
                prior_policy_digest=None,
                requested_by="platform-owner",
                reason="Invalid update without prior state.",
                requested_at=NOW,
                valid_until=NOW + timedelta(hours=1),
            )

    def test_signature_window_cannot_outlive_change_request(self) -> None:
        request = self._tenant_request()
        with self.assertRaises(ChangeControlError):
            change_signature_request(
                request,
                issuer="bank-a-change-ca",
                subject="config-governor-user",
                key_id="config-2026",
                role="configuration_governor",
                issued_at=NOW + timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=3),
            )

    def test_top_level_help_surfaces_change_control_commands(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(entrypoint(["--help"]), 0)
        rendered = output.getvalue()
        self.assertIn("tenant-policy-change-request", rendered)
        self.assertIn("change-signature-request", rendered)
        self.assertIn("resolve-change-control", rendered)
        self.assertIn("verify-change-control", rendered)


if __name__ == "__main__":
    unittest.main()
