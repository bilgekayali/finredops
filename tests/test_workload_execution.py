from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finredops.crypto_provider import ProviderSignature
from finredops.institution import InstitutionKeyReference, InstitutionSecurityContext
from finredops.models import ExecutionReceipt, ExecutionStatus, PolicyDecision, sha256_digest
from finredops.workload_execution import (
    EgressRule,
    EmergencyStopState,
    OneTimeTestAccountGrant,
    WorkerExecutionEnvelope,
    WorkloadExecutionError,
    build_execution_lease,
    execute_with_isolated_worker,
    network_policy_digest,
    verify_execution_lease,
    verify_signed_worker_result,
)
from finredops.workload_identity import (
    create_workload_identity_attestation,
    sign_worker_receipt,
    verify_workload_identity_attestation,
)
from finredops.workload_ledger import SQLiteOneTimeGrantLedger

from tests.helpers import NOW, make_engagement, make_proposal


class SigningProvider:
    provider_name = "other"

    def __init__(self) -> None:
        self.keys = {"hsm://workload-v1": Ed25519PrivateKey.generate()}

    def sign_digest(self, key_ref: str, digest: bytes) -> ProviderSignature:
        return ProviderSignature(self.keys[key_ref].sign(digest), "ED25519")

    def verify_digest(self, key_ref: str, digest: bytes, signature: ProviderSignature) -> bool:
        if signature.algorithm != "ED25519":
            return False
        try:
            self.keys[key_ref].public_key().verify(signature.signature, digest)
        except InvalidSignature:
            return False
        return True


class FakeIsolatedWorker:
    worker_id = "worker-a"
    deployment_id = "deploy-2026-08"
    isolation_profile = "external-sandbox-v1"

    def __init__(self, context: InstitutionSecurityContext, provider: SigningProvider) -> None:
        self.context = context
        self.provider = provider
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        evidence = {
            "source": "synthetic isolated worker",
            "network_activity": True,
            "request": {"method": "HEAD", "request_count": 1},
            "response_body_collected": False,
            "redirect_followed": False,
        }
        receipt = ExecutionReceipt(
            execution_id="EXEC-WORKER-001",
            proposal_id=request.proposal.proposal_id,
            proposal_digest=request.proposal.digest(),
            status=ExecutionStatus.VALIDATED,
            runner="external-isolated-worker:v1",
            started_at=NOW,
            finished_at=NOW + timedelta(seconds=1),
            evidence=evidence,
            evidence_digest=sha256_digest(evidence),
        )
        envelope = WorkerExecutionEnvelope(
            institution_id=self.context.institution_id,
            worker_id=self.worker_id,
            deployment_id=self.deployment_id,
            execution_id=receipt.execution_id,
            workload_identity_digest=request.identity.digest(),
            lease_digest=request.lease.digest(),
            test_account_grant_digest=request.test_account.digest(),
            egress_rule_digest=request.egress_rule.digest(),
            emergency_stop_state_digest=request.emergency_stop.digest(),
            observed_peer_address="203.0.113.10",
            request_count=1,
            account_grant_consumed=True,
            receipt=receipt,
        )
        signature = sign_worker_receipt(
            institution_context=self.context,
            provider=self.provider,
            identity=request.identity,
            execution_id=receipt.execution_id,
            execution_envelope_digest=envelope.digest(),
            lease_digest=request.lease.digest(),
            signed_at=NOW + timedelta(seconds=1),
        )
        return envelope, signature


def context(institution_id: str = "bank-a") -> InstitutionSecurityContext:
    return InstitutionSecurityContext(
        institution_id=institution_id,
        institution_name="Example Bank",
        key_references=(
            InstitutionKeyReference(
                key_id="data-v1",
                purpose="data_encryption",
                provider="other",
                key_ref="kms://data-v1",
            ),
            InstitutionKeyReference(
                key_id="audit-v1",
                purpose="audit_signing",
                provider="other",
                key_ref="hsm://audit-v1",
            ),
            InstitutionKeyReference(
                key_id="workload-v1",
                purpose="workload_identity",
                provider="other",
                key_ref="hsm://workload-v1",
            ),
        ),
    )


def objects():
    institution = context()
    provider = SigningProvider()
    engagement = make_engagement()
    proposal = make_proposal(
        engagement,
        action_id="http.security_posture.validate",
        parameters={
            "port": 443,
            "path": "/health",
            "timeout_seconds": 5,
            "change_reference": "CHG-001",
            "methodology_profile": "tse-nist-owasp-v1",
        },
    )
    policy = PolicyDecision(
        allowed=True,
        code="ALLOW_CONTROLLED_VALIDATION",
        reasons=("synthetic approved boundary",),
        proposal_digest=proposal.digest(),
        decided_at=NOW,
    )
    egress = EgressRule(
        action_id=proposal.action_id,
        target=proposal.target,
        port=443,
        path="/health",
        peer_cidrs=("203.0.113.0/24",),
    )
    identity = create_workload_identity_attestation(
        institution_context=institution,
        provider=provider,
        worker_id="worker-a",
        deployment_id="deploy-2026-08",
        isolation_profile="external-sandbox-v1",
        runtime_image_digest="1" * 64,
        network_policy_digest=network_policy_digest(egress),
        isolation_evidence_digest="2" * 64,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    grant = OneTimeTestAccountGrant(
        grant_id="GRANT-001",
        institution_id=institution.institution_id,
        engagement_id=engagement.engagement_id,
        account_id="test-account-001",
        account_reference_digest="3" * 64,
        proposal_digest=proposal.digest(),
        action_id=proposal.action_id,
        target=proposal.target,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=20),
    )
    stop = EmergencyStopState(
        institution_id=institution.institution_id,
        engagement_id=engagement.engagement_id,
        generation=4,
        stopped=False,
        reason="Execution enabled for approved window.",
        changed_at=NOW - timedelta(minutes=2),
    )
    lease = build_execution_lease(
        institution_context=institution,
        proposal=proposal,
        engagement=engagement,
        policy_decision=policy,
        identity=identity,
        test_account=grant,
        egress_rule=egress,
        emergency_stop=stop,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=5),
    )
    return institution, provider, engagement, proposal, policy, egress, identity, grant, stop, lease


class WorkloadExecutionTests(unittest.TestCase):
    def test_workload_identity_is_short_lived_and_kms_verified(self) -> None:
        institution, provider, *_rest = objects()
        identity = _rest[4]
        self.assertTrue(
            verify_workload_identity_attestation(
                identity,
                institution_context=institution,
                provider=provider,
                as_of=NOW,
            )
        )
        self.assertFalse(identity.control_plane_embedded)
        self.assertFalse(identity.private_key_embedded)

    def test_execution_lease_binds_policy_identity_account_egress_and_stop(self) -> None:
        institution, _provider, engagement, proposal, policy, egress, identity, grant, stop, lease = objects()
        self.assertTrue(
            verify_execution_lease(
                lease,
                institution_context=institution,
                proposal=proposal,
                engagement=engagement,
                policy_decision=policy,
                identity=identity,
                test_account=grant,
                egress_rule=egress,
                emergency_stop=stop,
                as_of=NOW,
            )
        )
        self.assertFalse(
            verify_execution_lease(
                lease,
                institution_context=institution,
                proposal=proposal,
                engagement=engagement,
                policy_decision=replace(policy, allowed=False),
                identity=identity,
                test_account=grant,
                egress_rule=egress,
                emergency_stop=stop,
                as_of=NOW,
            )
        )

    def test_emergency_stop_fails_closed_before_worker_call(self) -> None:
        institution, provider, engagement, proposal, policy, egress, identity, grant, stop, lease = objects()
        worker = FakeIsolatedWorker(institution, provider)
        with tempfile.TemporaryDirectory() as temp:
            ledger = SQLiteOneTimeGrantLedger(Path(temp) / "grants.db")
            with self.assertRaises(WorkloadExecutionError):
                execute_with_isolated_worker(
                    institution_context=institution,
                    crypto_provider=provider,
                    worker_provider=worker,
                    grant_ledger=ledger,
                    proposal=proposal,
                    engagement=engagement,
                    policy_decision=policy,
                    identity=identity,
                    test_account=grant,
                    egress_rule=egress,
                    lease=lease,
                    emergency_stop_supplier=lambda: replace(stop, stopped=True, reason="Operator stop"),
                    now=NOW,
                )
        self.assertEqual(worker.calls, 0)

    def test_one_time_grant_prevents_replay(self) -> None:
        institution, provider, engagement, proposal, policy, egress, identity, grant, stop, lease = objects()
        worker = FakeIsolatedWorker(institution, provider)
        with tempfile.TemporaryDirectory() as temp:
            ledger = SQLiteOneTimeGrantLedger(Path(temp) / "grants.db")
            envelope, signature = execute_with_isolated_worker(
                institution_context=institution,
                crypto_provider=provider,
                worker_provider=worker,
                grant_ledger=ledger,
                proposal=proposal,
                engagement=engagement,
                policy_decision=policy,
                identity=identity,
                test_account=grant,
                egress_rule=egress,
                lease=lease,
                emergency_stop_supplier=lambda: stop,
                now=NOW,
            )
            self.assertTrue(
                verify_signed_worker_result(
                    envelope,
                    signature,
                    institution_context=institution,
                    crypto_provider=provider,
                    identity=identity,
                    test_account=grant,
                    egress_rule=egress,
                    lease=lease,
                    emergency_stop=stop,
                )
            )
            with self.assertRaises(WorkloadExecutionError):
                execute_with_isolated_worker(
                    institution_context=institution,
                    crypto_provider=provider,
                    worker_provider=worker,
                    grant_ledger=ledger,
                    proposal=proposal,
                    engagement=engagement,
                    policy_decision=policy,
                    identity=identity,
                    test_account=grant,
                    egress_rule=egress,
                    lease=lease,
                    emergency_stop_supplier=lambda: stop,
                    now=NOW,
                )
        self.assertEqual(worker.calls, 1)

    def test_peer_outside_signed_egress_policy_is_rejected(self) -> None:
        institution, provider, _engagement, _proposal, _policy, egress, identity, grant, stop, lease = objects()
        worker = FakeIsolatedWorker(institution, provider)
        request_objects = objects()
        _i, _p, engagement, proposal, policy, _e, _id, _g, _s, _l = request_objects
        envelope, signature = worker.execute(
            type("Request", (), {
                "proposal": proposal,
                "engagement": engagement,
                "lease": lease,
                "identity": identity,
                "test_account": grant,
                "egress_rule": egress,
                "emergency_stop": stop,
            })()
        )
        changed = replace(envelope, observed_peer_address="198.51.100.10")
        self.assertFalse(
            verify_signed_worker_result(
                changed,
                signature,
                institution_context=institution,
                crypto_provider=provider,
                identity=identity,
                test_account=grant,
                egress_rule=egress,
                lease=lease,
                emergency_stop=stop,
            )
        )

    def test_cross_institution_identity_fails_closed(self) -> None:
        institution, provider, engagement, proposal, policy, egress, identity, grant, stop, lease = objects()
        other = context("bank-b")
        self.assertFalse(
            verify_execution_lease(
                lease,
                institution_context=other,
                proposal=proposal,
                engagement=engagement,
                policy_decision=policy,
                identity=identity,
                test_account=grant,
                egress_rule=egress,
                emergency_stop=stop,
                as_of=NOW,
            )
        )


if __name__ == "__main__":
    unittest.main()
