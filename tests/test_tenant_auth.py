from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from finredops.entrypoint import entrypoint
from finredops.institution import InstitutionKeyReference, InstitutionSecurityContext
from finredops.models import sha256_digest
from finredops.oidc_identity import OIDCIdentityVerification
from finredops.store import SQLiteGovernanceStore
from finredops.tenant_auth import (
    AuthorizedTenantSession,
    TenantAuthorizationError,
    TenantRoutingPolicy,
    TenantSubjectGrant,
    authorize_tenant_route,
    tenant_authorization_from_document,
    tenant_policy_from_document,
    tenant_policy_template,
    verify_tenant_authorization,
)

NOW = datetime(2026, 8, 13, 9, 0, tzinfo=timezone.utc)


def _context(institution_id: str) -> InstitutionSecurityContext:
    return InstitutionSecurityContext(
        institution_id=institution_id,
        institution_name=f"{institution_id} Financial Institution",
        key_references=(
            InstitutionKeyReference(
                key_id="data-current",
                purpose="data_encryption",
                provider="other",
                key_ref=f"{institution_id}/data/current",
            ),
            InstitutionKeyReference(
                key_id="audit-current",
                purpose="audit_signing",
                provider="other",
                key_ref=f"{institution_id}/audit/current",
            ),
        ),
    )


def _verification(
    *,
    subject: str = "user-123",
    provider_id: str = "bank-idp",
    provider_config_digest: str = "1" * 64,
) -> OIDCIdentityVerification:
    core = {
        "provider_id": provider_id,
        "provider_config_digest": provider_config_digest,
        "jwks_digest": "2" * 64,
        "issuer": "https://idp.example.test",
        "client_id": "finredops-client",
        "subject": subject,
        "roles": ("qualified_tester", "review_governor"),
        "acr": "urn:example:aal2",
        "token_kid": "kid-2026",
        "token_algorithm": "RS256",
        "token_digest": "3" * 64,
        "nonce_digest": "4" * 64,
        "issued_at": int((NOW - timedelta(minutes=1)).timestamp()),
        "expires_at": int((NOW + timedelta(hours=1)).timestamp()),
        "auth_time": int((NOW - timedelta(minutes=2)).timestamp()),
        "verified_at": NOW,
    }
    verification_id = f"FRX-OIDC-{sha256_digest(core)[:24].upper()}"
    return OIDCIdentityVerification(verification_id=verification_id, **core)


def _policy(
    institution_id: str = "bank-a",
    provider_id: str = "bank-idp",
    provider_config_digest: str = "1" * 64,
) -> TenantRoutingPolicy:
    return TenantRoutingPolicy(
        policy_id=f"{institution_id}-routing-v1",
        institution_id=institution_id,
        oidc_provider_id=provider_id,
        oidc_provider_config_digest=provider_config_digest,
        grants=(
            TenantSubjectGrant(
                subject="user-123",
                roles=("qualified_tester", "review_governor"),
                capabilities=("store_read", "store_write", "audit_verify"),
            ),
        ),
    )


class TenantAuthorizationTests(unittest.TestCase):
    def test_authorization_round_trip_binds_oidc_policy_and_institution_context(self) -> None:
        verification = _verification()
        policy = _policy()
        context = _context("bank-a")
        authorization = authorize_tenant_route(
            verification,
            policy,
            context,
            requested_capabilities=("store_read", "audit_verify"),
            as_of=NOW + timedelta(minutes=5),
        )
        restored = tenant_authorization_from_document(authorization.as_dict())
        self.assertEqual(restored.authorization_id, authorization.authorization_id)
        self.assertEqual(restored.institution_context_digest, context.digest())
        self.assertEqual(restored.policy_digest, policy.digest())
        self.assertEqual(restored.verification_digest, verification.as_dict()["verification_digest"])
        verify_tenant_authorization(
            restored,
            verification,
            policy,
            context,
            as_of=NOW + timedelta(minutes=10),
        )

    def test_cross_institution_replay_fails_closed(self) -> None:
        verification = _verification()
        policy = _policy("bank-a")
        authorization = authorize_tenant_route(
            verification,
            policy,
            _context("bank-a"),
            requested_capabilities=("store_read",),
            as_of=NOW + timedelta(minutes=5),
        )
        with self.assertRaises(TenantAuthorizationError):
            verify_tenant_authorization(
                authorization,
                verification,
                policy,
                _context("bank-b"),
                as_of=NOW + timedelta(minutes=10),
            )

    def test_provider_subject_and_provider_configuration_are_exact_not_advisory(self) -> None:
        with self.assertRaises(TenantAuthorizationError):
            authorize_tenant_route(
                _verification(provider_id="other-idp"),
                _policy(),
                _context("bank-a"),
                requested_capabilities=("store_read",),
                as_of=NOW + timedelta(minutes=5),
            )
        with self.assertRaises(TenantAuthorizationError):
            authorize_tenant_route(
                _verification(provider_config_digest="9" * 64),
                _policy(),
                _context("bank-a"),
                requested_capabilities=("store_read",),
                as_of=NOW + timedelta(minutes=5),
            )
        with self.assertRaises(TenantAuthorizationError):
            authorize_tenant_route(
                _verification(subject="other-user"),
                _policy(),
                _context("bank-a"),
                requested_capabilities=("store_read",),
                as_of=NOW + timedelta(minutes=5),
            )

    def test_template_pins_provider_configuration_and_uses_bounded_policy_id(self) -> None:
        context = _context("bank-a")
        verification = _verification()
        document = tenant_policy_template(context=context, verification=verification)
        policy = tenant_policy_from_document(document)
        self.assertEqual(policy.oidc_provider_config_digest, verification.provider_config_digest)
        self.assertTrue(policy.policy_id.startswith("FRX-TRP-"))
        self.assertLessEqual(len(policy.policy_id), 200)

    def test_capability_escalation_is_rejected(self) -> None:
        grant = TenantSubjectGrant(
            subject="user-123",
            roles=("qualified_tester",),
            capabilities=("store_read",),
        )
        policy = TenantRoutingPolicy(
            policy_id="bank-a-routing-v1",
            institution_id="bank-a",
            oidc_provider_id="bank-idp",
            oidc_provider_config_digest="1" * 64,
            grants=(grant,),
        )
        with self.assertRaises(TenantAuthorizationError):
            authorize_tenant_route(
                _verification(),
                policy,
                _context("bank-a"),
                requested_capabilities=("store_read", "store_write"),
                as_of=NOW + timedelta(minutes=5),
            )

    def test_policy_change_invalidates_previously_issued_authorization(self) -> None:
        verification = _verification()
        policy = _policy()
        context = _context("bank-a")
        authorization = authorize_tenant_route(
            verification,
            policy,
            context,
            requested_capabilities=("store_read",),
            as_of=NOW + timedelta(minutes=5),
        )
        changed = TenantRoutingPolicy(
            policy_id=policy.policy_id,
            institution_id=policy.institution_id,
            oidc_provider_id=policy.oidc_provider_id,
            oidc_provider_config_digest=policy.oidc_provider_config_digest,
            grants=(
                TenantSubjectGrant(
                    subject="user-123",
                    roles=("review_governor",),
                    capabilities=("store_read",),
                ),
            ),
        )
        with self.assertRaises(TenantAuthorizationError):
            verify_tenant_authorization(
                authorization,
                verification,
                changed,
                context,
                as_of=NOW + timedelta(minutes=10),
            )

    def test_expired_oidc_cannot_authorize_or_revalidate_route(self) -> None:
        verification = _verification()
        policy = _policy()
        context = _context("bank-a")
        authorization = authorize_tenant_route(
            verification,
            policy,
            context,
            requested_capabilities=("store_read",),
            as_of=NOW + timedelta(minutes=5),
        )
        with self.assertRaises(TenantAuthorizationError):
            verify_tenant_authorization(
                authorization,
                verification,
                policy,
                context,
                as_of=NOW + timedelta(hours=2),
            )
        with self.assertRaises(TenantAuthorizationError):
            authorize_tenant_route(
                verification,
                policy,
                context,
                requested_capabilities=("store_read",),
                as_of=NOW + timedelta(hours=2),
            )

    def test_policy_and_authorization_documents_are_digest_bound(self) -> None:
        policy_document = _policy().as_dict()
        policy_document["institution_id"] = "bank-b"
        with self.assertRaises(TenantAuthorizationError):
            tenant_policy_from_document(policy_document)

        authorization = authorize_tenant_route(
            _verification(),
            _policy(),
            _context("bank-a"),
            requested_capabilities=("store_read",),
            as_of=NOW + timedelta(minutes=5),
        ).as_dict()
        authorization["subject"] = "other-user"
        with self.assertRaises(TenantAuthorizationError):
            tenant_authorization_from_document(authorization)

    def test_authorized_session_selects_exact_tenant_and_blocks_unprotected_write(self) -> None:
        verification = _verification()
        policy = _policy()
        context = _context("bank-a")
        authorization = authorize_tenant_route(
            verification,
            policy,
            context,
            requested_capabilities=("store_read", "store_write"),
            as_of=NOW + timedelta(minutes=5),
        )
        session = AuthorizedTenantSession.create(
            authorization,
            verification,
            policy,
            context,
            as_of=NOW + timedelta(minutes=10),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tenant.db"
            with SQLiteGovernanceStore(path, institution_id="bank-b"):
                pass
            with session.open_store(path, access="read") as store:
                self.assertEqual(store.metadata()["institution_id"], "bank-a")
            with self.assertRaises(TenantAuthorizationError):
                session.open_store(path, access="write")

    def test_top_level_help_surfaces_authenticated_tenant_commands(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(entrypoint(["--help"]), 0)
        rendered = output.getvalue()
        self.assertIn("authorize-tenant-route", rendered)
        self.assertIn("verify-tenant-authorization", rendered)
        self.assertIn("authorized-tenant-store-metadata", rendered)


if __name__ == "__main__":
    unittest.main()
